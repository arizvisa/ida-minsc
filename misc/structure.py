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
import re, fnmatch, pickle, heapq, bisect

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
        ti = idaapi.tinfo_t()
        return interface.tinfo.concretize(ti) if get_tinfo(ti, ea) or guess_tinfo(ti, ea) != idaapi.GUESS_FUNC_FAILED else None
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

    @classmethod
    def structure(cls, sptr):
        '''Yield each structure member or reference that uses the structure identified by `sptr`.'''
        sptr = idaapi.get_struc(sptr if isinstance(sptr, types.integer) else sptr.id)
        for offset, reference_or_member in interface.xref.structure(sptr):
            if isinstance(reference_or_member, interface.refbase_t):
                reference = reference_or_member
                yield reference

            # Otherwise it is a tuple for a structure member, and we need to
            # use it to construct a structure_t and fetch the member by index.
            else:
                mowner, mcandidate = reference_or_member
                mindex = members.index(mowner, mcandidate)
                member = structure_t(mowner, offset).members[mindex]
                yield member
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
            #return name.startswith('field_')               # XXX: this is how the disassembler does it..
            field, offset = name.split('_', 1) if '_' in name else (name, '')
            expected = "{:x}".format(mptr.soff)
            return (field, offset.lower()) != ('field', expected)

        # first we'll check that it's not one of the names we can check with the disassembler api.
        idaname = utils.string.to(name)
        if idaapi.is_anonymous_member_name(idaname) or idaapi.is_special_member(mptr.id):
            return False

        # now we need to figure out the function and the boundaries of the frame
        # so that we can distinguish between variables, args, and preserved regs.
        ea = idaapi.get_func_by_frame(sptr.id)
        fn = idaapi.get_func(ea)
        if ea == idaapi.BADADDR or not fn:
            return any(name.startswith(prefix) for prefix in {'arg_', 'var_'})

        # we're now free to figure out which the frame part that this member
        # belongs to. we render the expected offset and do a comparison.
        args, frsize = idaapi.frame_off_args(fn), fn.frsize
        var, offset = name.split('_', 1) if '_' in name else (name, '')
        prefix, expected = ('var', "{:x}".format(frsize - mptr.soff)) if mptr.soff < args else ('arg', "{:x}".format(mptr.soff - args))
        return (var, offset.lower()) != (prefix, expected)

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
        ok = idaapi.retrieve_member_info(mptr, opinfo) if idaapi.__version__ < 7.0 else idaapi.retrieve_member_info(opinfo, mptr)
        tid = opinfo.tid if ok else idaapi.BADNODE

        # now we can dissolve it the type, grab the type information,
        # and use them to return a tuple containing everything we collected.
        dissolved = interface.typemap.dissolve(mptr.flag, tid, msize, offset=moffset)
        return mptr.id, mname, dissolved, location, cls.get_typeinfo(mptr), mcomments

    @classmethod
    def has_references(cls, mptr):
        '''Return whether the member specified by `mptr` is referenced by an address within the database.'''
        identifier = mptr if isinstance(mptr, types.integer) else mptr.id
        packed = idaapi.get_member_by_id(identifier)
        if not packed:
            return False
        mptr, fullname, owner = packed

        # Figure out whether we need check an xref list for a frame or just use the regular xrefs.
        fn, is_union, is_frame = idaapi.get_func_by_frame(owner.id), union(owner), frame(owner)

        # If it's a function frame, collect an xref list and return true if it's not empty.
        if interface.node.identifier(owner.id) and is_frame and fn != idaapi.BADADDR:
            iterable = (True for ea, opnum, xtype in interface.xref.frame(fn, mptr))
            return next(iterable, False)

        # Otherwise, we just need an xref that points to a valid address in the database. For
        # performance, we determine this by assuming an address if it's not an identifier.
        iterable = (ea for ea, iscode, xtype in interface.xref.to(mptr.id, idaapi.XREF_ALL))
        return next((True for ea in iterable if not interface.node.identifier(ea)), False)

    @classmethod
    def references(cls, mptr):
        '''Return a list of all the operand references in the database for the member specified by `mptr`.'''
        FF_STRUCT = idaapi.FF_STRUCT if hasattr(idaapi, 'FF_STRUCT') else idaapi.FF_STRU
        Fnetnode, Fidentifier = (getattr(idaapi, api, utils.fidentity) for api in ['ea2node', 'node2ea'])
        FF_STROFF = idaapi.stroff_flag() if hasattr(idaapi, 'stroff_flag') else idaapi.stroffflag()
        FF_STKVAR = idaapi.stkvar_flag() if hasattr(idaapi, 'stkvar_flag') else idaapi.stkvarflag()

        # first we'll need to know the structure that owns the member.
        identifier = mptr if isinstance(mptr, types.integer) else mptr.id
        packed = idaapi.get_member_by_id(identifier)
        if not packed:
            raise E.MemberNotFoundError(u"{:s}.references({:#x}) : Unable to find a member with the specified identifier ({:#x}).".format('.'.join([__name__, cls.__name__]), identifier, identifier))
        mptr, fullname, owner = packed

        # start out by grabbing attributes that we need to know about the structure.
        fn, is_union, is_frame = idaapi.get_func_by_frame(owner.id), union(owner), frame(owner)

        # if structure is a frame, then we need to build an xref list
        # to the member in order to return all of its references.
        #if interface.node.identifier(owner.id) and internal.netnode.name.get(Fnetnode(owner.id)).startswith('$ '):
        if interface.node.identifier(owner.id) and is_frame and fn != idaapi.BADADDR:
            results = []

            # now we can collect all the xrefs to the member within the function
            for ea, opnum, xtype in interface.xref.frame(fn, mptr):
                access = [item.access for item in interface.instruction.access(ea)]
                results.append(interface.opref_t(ea, opnum, interface.access_t(xtype, True)))

            # include any xrefs too in case the user (or the database) has
            # explicitly referenced the frame variable using a structure path.
            for ea, iscode, xtype in interface.xref.to(mptr.id, idaapi.XREF_ALL):
                flags, access = interface.address.flags(ea, idaapi.MS_0TYPE|idaapi.MS_1TYPE), [item.access for item in interface.instruction.access(ea)]

                # first we need to figure out which operand the reference is
                # referring to. if we couldn't find any, then complain about it.
                listable = [(opnum, operand, address.opinfo(ea, opnum)) for opnum, operand in enumerate(address.operands(ea)) if address.opinfo(ea, opnum)]
                if not listable:
                    logging.debug(u"{:s}.references({:#x}) : Skipping reference at {:#x} to member ({:#x}) with flags ({:#x}) due to the address having no operand information.".format('.'.join([__name__, cls.__name__]), mptr.id, ea, mptr.id, address.flags(ea)))

                # if our flags represent a structure offset (they should), then we
                # use the structure path to find the operand that exists.
                elif flags & FF_STROFF in {FF_STROFF, idaapi.FF_0STRO, idaapi.FF_1STRO}:
                    logging.debug(u"{:s}.references({:#x}) : Found {:s} reference at {:#x} to member ({:#x}) with flags ({:#x}).".format('.'.join([__name__, cls.__name__]), mptr.id, 'FF_STROFF', ea, mptr.id, address.flags(ea)))
                    iterable = [(opnum, idaapi.as_signed(op.value if op.type in {idaapi.o_imm} else op.addr), interface.node.get_stroff_path(ea, opnum)) for opnum, op, _ in listable]
                    iterable = ((opnum, interface.strpath.of_tids(delta + value, tids)) for opnum, value, (delta, tids) in iterable if tids)
                    iterable = ((opnum, {member.id for _, member, _ in path}) for opnum, path in iterable)
                    iterable = ((opnum, access[opnum]) for opnum, identifiers in iterable if mptr.id in identifiers)
                    results.extend(interface.opref_t(ea, opnum, interface.access_t(xtype, iscode)) for opnum, opaccess in iterable)

                # if we couldn't figure it out, then we log a warning and bail.
                # there really shouldn't be any other operand flag for a stkvar.
                else:
                    logging.warning(u"{:s}.references({:#x}) : Skipping reference at {:#x} to member ({:#x}) with flags ({:#x}) due to the operand type being unexpected.".format('.'.join([__name__, cls.__name__]), mptr.id, ea, mptr.id, address.flags(ea)))
                continue
            return results

        # otherwise, it's a structure..which means we need to specify the member to get refs for
        refs = [packed_frm_iscode_type for packed_frm_iscode_type in interface.xref.to(mptr.id, idaapi.XREF_ALL)]

        # collect the identifiers of all of the members (children) that can possibly refer to
        # this same one which means we track unions as well. this requires us to recursively
        # walk through all of the references for each parent until we've collected everything.
        parents, children, queue, table = {owner.id}, {mptr.id}, {owner.id}, {owner.id : owner, mptr.id : mptr}
        while True:
            work = {item for item in []}

            # now that we have our work, we can add it to our list. however, we also
            # need to check if our parent is a union so that we can descend through
            # its members for ones at the same offset of our referring member.
            for _, item in itertools.chain(*map(interface.xref.structure, queue)):
                if isinstance(item, interface.ref_t):
                    continue

                # unpack the item and then check if it's a frame, since we can skip those too.
                mowner, mmember = item
                if frame(mowner):
                    continue
                mrealoffset = 0 if union(mowner) else mmember.soff
                table[mowner.id] = mowner
                table[mmember.id ] = mmember

                # if it's a union, then update the queue and our collection of children.
                if union(mowner):
                    candidates = [mcandidate for _, _, mcandidate in members.iterate(mowner)]
                    table.update((mcandidate.id, mcandidate) for mcandidate in candidates)
                    children.update(mcandidate.id for mcandidate in candidates if member.contains(mcandidate, mrealoffset))

                    candidates = [idaapi.get_sptr(mcandidate) for mcandidate in candidates if idaapi.get_sptr(mcandidate)]
                    table.update((mchild.id, mchild) for mchild in iterable)
                    work.update(mchild.id for mchild in iterable)

                work.add(mowner.id), children.add(mmember.id)

            # If all of our work is already in our results (parents), then exit our loop.
            if work & parents == work:
                break

            # Otherwise we merge it, reload the queue with our new work, and try..try...again.
            parents, queue = parents | work, work - parents

        # okay, now we can convert this set into a set of structures and members to look for
        iterable = (idaapi.get_member_by_id(id) for id in children if idaapi.get_member_by_id(id))
        candidates = {id for id in itertools.chain(*([mowner.id, mchild.id] for mowner, _, mchild in iterable))}

        # now figure out which operand has the structure member applied to it
        results = []
        for ea, iscode, xtype in refs:
            flags, access = interface.address.flags(ea, idaapi.MS_0TYPE|idaapi.MS_1TYPE), [item.access for item in interface.instruction.access(ea)]
            listable = [(opnum, operand, address.opinfo(ea, opnum)) for opnum, operand in enumerate(address.operands(ea)) if address.opinfo(ea, opnum)]

            # If we have any stack operands, then figure out which ones contain it. Fortunately,
            # we don't have to filter it through our candidates because IDA seems to get this right.
            if flags & FF_STKVAR in {FF_STKVAR, idaapi.FF_0STK, idaapi.FF_1STK}:
                logging.debug(u"{:s}.references({:#x}) : Found {:s} reference at {:#x} to member ({:#x}) with flags ({:#x}).".format('.'.join([__name__, cls.__name__]), mptr.id, 'FF_STKVAR', ea, mptr.id, address.flags(ea)))
                masks = [(idaapi.MS_0TYPE, idaapi.FF_0STK), (idaapi.MS_1TYPE, idaapi.FF_1STK)]
                iterable = ((opnum, access[opnum]) for opnum, (mask, ff) in enumerate(masks) if flags & mask == ff)
                results.extend(interface.opref_t(ea, opnum, interface.access_t(xtype, iscode)) for opnum, opaccess in iterable)

            # Otherwise, we skip this reference because it's not an operand reference, and is most
            # likely a member reference to a global structure that has been applied to an address.
            elif not listable:
                logging.debug(u"{:s}.references({:#x}) : Skipping reference at {:#x} to member ({:#x}) with flags ({:#x}) due to the address having no operand information.".format('.'.join([__name__, cls.__name__]), mptr.id, ea, mptr.id, address.flags(ea)))

            # If our flags mention a structure offset, then we can just get the structure path.
            elif flags & FF_STROFF in {FF_STROFF, idaapi.FF_0STRO, idaapi.FF_1STRO}:
                logging.debug(u"{:s}.references({:#x}) : Found {:s} reference at {:#x} to member ({:#x}) with flags ({:#x}).".format('.'.join([__name__, cls.__name__]), mptr.id, 'FF_STROFF', ea, mptr.id, address.flags(ea)))
                iterable = [(opnum, idaapi.as_signed(op.value if op.type in {idaapi.o_imm} else op.addr), interface.node.get_stroff_path(ea, opnum)) for opnum, op, _ in listable]
                iterable = ((opnum, interface.strpath.of_tids(delta + value, tids)) for opnum, value, (delta, tids) in iterable if tids)
                iterable = ((opnum, {member.id for _, member, _ in path}) for opnum, path in iterable)
                iterable = ((opnum, access[opnum]) for opnum, identifiers in iterable if identifiers & candidates)
                results.extend(interface.opref_t(ea, opnum, interface.access_t(xtype, iscode)) for opnum, opaccess in iterable)

            # Otherwise, we need to extract the information from the operand's refinfo_t. We
            # filter these by only taking the ones which we can use to calculate the target.
            else:
                logging.debug(u"{:s}.references({:#x}) : Found operand reference at {:#x} to member ({:#x}) with flags ({:#x}).".format('.'.join([__name__, cls.__name__]), mptr.id, ea, mptr.id, address.flags(ea)))
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
    def nearest(cls, sptr, offset):
        '''Return the member from the structure identified by `sptr` that is at or before the given `offset`.'''
        available = [packed for packed in cls.iterate(sptr)]
        while len(available) > 1:
            index = len(available) // 2
            sptr, mindex, mptr = available[index]
            pivot = 0 if mptr.flag & idaapi.MF_UNIMEM else mptr.soff
            available = available[:index] if offset < pivot else available[index:]
        return available[0] if available else None

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
    def in_offset(cls, sptr, offset):
        '''Yield the members from the union identified by `sptr` at the given `offset`.'''
        get_data_elsize = idaapi.get_full_data_elsize if hasattr(idaapi, 'get_full_data_elsize') else idaapi.get_data_elsize
        FF_STRUCT = idaapi.FF_STRUCT if hasattr(idaapi, 'FF_STRUCT') else idaapi.FF_STRU
        FF_STRLIT = idaapi.FF_STRLIT if hasattr(idaapi, 'FF_STRLIT') else idaapi.FF_ASCI
        FF_MASKSIZE = idaapi.as_uint32(idaapi.DT_TYPE)
        candidates = [(sptr, mindex, mptr) for sptr, mindex, mptr in cls.at_offset(sptr, offset)]

        # XXX: We do special handling for unions so that we prioritize members that start
        #      at the _exact_ offset and members are more recent. This way if the caller
        #      just asks for the member for an offset, we can hopefully guess the exact
        #      member that they were referring to. This requires us to handle arrays, and
        #      dig into any members that are structures to see if the offset is accurate.

        # XXX: The intention of this complicated logic is so that when we try to resolve
        #      the union path for an operand, we choose the most accurate members for it.

        # First we give out the mandatory warning that we're making a decision for them.
        iterable = (idaapi.get_member_fullname(mptr.id) for _, _, mptr in candidates)
        if len(candidates) > 1:
            logging.warning(u"{:s}.in_offset({:#x}, {:+#x}) : The specified offset ({:#x}) is currently occupied by more than one member ({:s}).".format('.'.join([__name__, cls.__name__]), sptr.id, offset, offset, ', '.join(map(utils.string.to, iterable))))

        # Then we grab the operand information for each member so that we can check them.
        typeinfo = []
        for _, _, mptr in candidates:
            opinfo = idaapi.opinfo_t()
            ok = idaapi.retrieve_member_info(mptr, opinfo) if idaapi.__version__ < 7.0 else idaapi.retrieve_member_info(opinfo, mptr)
            typeinfo.append((mptr.flag, opinfo.tid if ok else None, idaapi.get_member_size(mptr)))

        # Now we iterate through our candidates so that we can select the best order.
        selected = []
        for candidate, packed_type in zip(candidates, typeinfo):
            sptr, mindex, mptr = candidate
            opinfo, realoffset = idaapi.opinfo_t(), offset - (0 if union(sptr) else mptr.soff)

            # First thing is that we need to grab the member's type information. We'll
            # be using this to determine what score this candidate will get in our heap.
            FF, retrieved = mptr.flag & FF_MASKSIZE, idaapi.retrieve_member_info(mptr, opinfo) if idaapi.__version__ < 7.0 else idaapi.retrieve_member_info(opinfo, mptr)
            melement, msize = get_data_elsize(mptr.id, mptr.flag, opinfo if retrieved else None), idaapi.get_member_size(mptr)

            # Now we'll check to see if it's an array, because this might actually be
            # an array of structures that if so then we can fall through to handle it.
            # First check if it's a structure because we need to dig into it to
            # see if the offset references the beginning of one of its members.
            index, inexactness = divmod(realoffset, melement)

            # This is a base type, so we simply prioritize it high.
            if not retrieved:
                priority = -2 if msize == melement and not inexactness else -1 if not inexactness else 0

            # If this is a structure, then set it to a value that we can scale based on accuracy.
            elif retrieved and FF in {FF_STRUCT, FF_STRLIT}:
                priority = -3 if msize == melement and not inexactness else -2 if not inexactness else -1

            # This is an unknown, so it's probably a custom type. We choose these as the very last.
            else:
                priority = 3 if msize == melement and not inexactness else 4 if not inexactness else 5

            # Now if we found a structure, we increase the priority if the offset references
            # one of its members. It would be better if we traversed the structure in case
            # it's a union, but our goal is to just be better than the disassembler.
            mstruc = idaapi.get_sptr(mptr)
            if mstruc:
                mchild = idaapi.get_member(mstruc, realoffset)
                moffset = realoffset - (0 if union(mstruc) else mchild.soff)
                index, inexactness = member.at(mchild, moffset) if mchild else (0, 0)
                priority *= 3 if mchild and not moffset and not inexactness else 2 if mchild and not inexactness else 1

            # Then we can add it to the heap and continue onto the next member.
            heapq.heappush(selected, (priority, candidate))

        # Now we log the order of the members that we prioritized, just in case this
        # "algorithm" is totally busted when used, and so that we can figure out where
        # it's busted. It probably is, because I'm not 100% what it's actually doing.
        ordered = [candidate for priority, candidate in heapq.nsmallest(len(selected), selected)]
        iterable = ((sptr, mptr, idaapi.get_member_fullname(mptr.id)) for sptr, mindex, mptr in ordered)
        messages = (u"[{:d}] {:s} {:#x}{:+#x}".format(1 + index, fullname, 0 if union(sptr) else mptr.soff, mptr.eoff) for index, (sptr, mptr, fullname) in enumerate(iterable))
        [ logging.info(msg) for msg in messages ]

        # Finally we can yield our candidates with the hope that if a
        # structure path is built from them, it "might" appear intuitive.
        for sptr, mindex, mptr in ordered:
            yield sptr, mindex, mptr
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

    @classmethod
    def references(cls, sptr):
        '''Return the structure members and operand references that reference the structure identified by `sptr`.'''
        Fnetnode = getattr(idaapi, 'ea2node', utils.fidentity)

        # First collect all of our identifiers referenced by this structure,
        # whilst making sure to include all the members too.
        iterable = itertools.chain([sptr.id], (mptr.id for sptr, mindex, mptr in cls.iterate(sptr)))
        identifiers = {identifier for identifier in iterable}

        # Now we need to iterate through all of our members and grab all references to
        # absolutely everything. This is pretty much bypassing the "cross-reference depth"
        # option since if the user is using the api, they probably want everything anywayz.
        ichainable = (interface.xref.to(identifier, idaapi.XREF_ALL) for identifier in identifiers)
        refs = [packed_frm_iscode_type for packed_frm_iscode_type in itertools.chain(*ichainable)]

        # That should've given us absolutely every reference related to this
        # structure, so the last thing to do is to filter each of the items
        # in our list for references pointing to addresses within the database.
        results, matches = {}, {identifier for identifier in identifiers}
        for xrfrom, xriscode, xrtype in refs:
            flags = address.flags(xrfrom)

            # If the reference is an identifier, then it's not what we're looking
            # for as this method only cares about database addresses.
            if interface.node.identifier(xrfrom):
                continue

            # If the reference is not pointing to code, then we skip this because
            # there's no way it can actually be pointing to an operand.
            if not address.code(xrfrom):
                logging.debug(u"{:s}.references({:#x})) : Skipping {:s} reference at {:#x} with the type ({:d}) due to its address not being marked as code.".format('.'.join([__name__, cls.__name__]), sptr.id, 'code' if xriscode else 'data', xrfrom, xrtype))
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
                    candidates, not_a_member = {mptr.id for _, mptr, _ in path if mptr}, any(mptr is None for _, mptr, _ in path)

                    # Verify that one of our ids is contained within it unless the path is
                    # referencing the structure directly. If none of the members in the path
                    # are related to our structure, then we can just ignore this reference.
                    if not any([candidates & matches, not_a_member]):
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

        # Merge our collection of references for each address and then return them.
        merged = {ea : functools.reduce(operator.or_, items) for ea, items in results.items()}
        return [merged[ea] for ea in sorted(results)]

    @classmethod
    def at(cls, sptr, offset, *filter):
        """Traverse into the structure identified by `sptr` yielding each member located at the specified `offset`.

        If a closure is passed as the `filter` parameter, then use the function to filter the chosen candidates during descent.
        """
        base, selected = 0, [packed for packed in members.at_offset(sptr, int(offset))]
        candidates = [mptr for mowner, mindex, mptr in selected]
        table = {mptr.id : index for index, (_, _, mptr) in enumerate(selected)}

        # Filter all of our candidates and begin our traversal through them.
        count, [F] = 0, filter if filter else [lambda sptr, items: items]
        result, filtered = [], F(sptr, candidates) if len(candidates) > 1 else candidates
        while filtered:
            if len(filtered) == 1:
                [mptr] = filtered

                # If this member doesn't contain the offset for some reason, then bail.
                if not member.contains(mptr, offset):
                    break

                # Figure out the actual location into the member pointed to by the offset.
                index, remainder = member.at(mptr, offset)
                melement = member.element(mptr)
                res, mtype = index * melement, idaapi.get_sptr(mptr)

            # If we have more than one member to choose from and we're
            # in a union, then we immediately stop our traversal here.
            elif filtered and union(sptr):
                break

            # If it's not a union, then we assume the neareset member in
            # front of the offset. This way the full path is relative to it.
            elif filtered:
                choice = members.nearest(sptr, offset)
                if not choice:
                    break
                mowner, mindex, mptr = choice

                # Grab the location of the offset into the member.
                index, remainder = member.at(mptr, offset)
                melement = member.element(mptr)
                res, mtype = index * melement, idaapi.get_sptr(mptr)

            # Now we have a member to yield and can adjust our offset.
            base, offset, moffset, count = base, remainder, 0 if mptr.flag & idaapi.MF_UNIMEM else mptr.soff, count + 1
            yield base, selected[table[mptr.id]]

            # If we can't descend any farther, then we can leave.
            if not mtype:
                break

            # Adjust for the next iteration, and descend into the structure for the selected member.
            sptr, base = mtype, base + res + moffset
            selected = [packed for packed in members.at_offset(mtype, offset)]
            candidates = [mptr for mowner, mindex, mptr in selected]
            table = {mptr.id : index for index, (_, _, mptr) in enumerate(selected)}
            filtered = F(sptr, candidates) if len(candidates) > 1 else candidates

        # If we didn't return anything yet, then use the nearest member.
        if not count:
            choice = members.nearest(sptr, offset)
            mowner, mindex, mptr = choice
            index, remainder = member.at(mptr, offset)
            melement = member.element(mptr)
            yield base + index * melement, choice
        return

    @classmethod
    def slice(cls, sptr, slice):
        '''Return a `slice` of the contiguous list of members belonging to the structure identified by `sptr`.'''
        slice = slice if isinstance(slice, builtins.slice) else builtins.slice(slice, 1 + slice)
        start, stop, selected = interface.strpath.members(sptr, slice)

        # Now we just need to transform the elements we selected into the
        # member that was included or a size representing the empty space.
        iterable = (member_or_size for offset, member_or_size in selected)
        results = ((cls.by_identifier(sptr, member_or_size) if isinstance(member_or_size, idaapi.member_t) else member_or_size) for member_or_size in iterable)
        return [packed_or_size for packed_or_size in results]

    @classmethod
    def remove_slice(cls, sptr, slice, *offset):
        '''Remove a `slice` of the members belonging to the structure or union identified by `sptr`.'''
        sptr = idaapi.get_struc(sptr.id if isinstance(sptr, (idaapi.struc_t, structure_t)) else sptr)
        slice, size = slice if isinstance(slice, builtins.slice) else builtins.slice(slice, 1 + slice or None), idaapi.get_struc_size(sptr)

        # Determine if the structure is a frame so that we can avoid removing
        # members that might interfere with how the disassembler uses it.
        # that we shouldn't delete because it will break the frame.
        ea = idaapi.get_func_by_frame(sptr.id)
        fn = None if ea == idaapi.BADADDR else idaapi.get_func(ea)
        iterable = itertools.chain([idaapi.frame_off_savregs(fn)] if fn.frregs else [], [idaapi.frame_off_retaddr(fn)] if idaapi.get_frame_retsize(fn) else []) if fn else []
        specials = {idaapi.get_member(sptr, moffset).id for moffset in filter(functools.partial(idaapi.get_member, sptr), iterable)}

        # If we weren't given a base offset, then use what the disassembler would.
        if offset:
            [base] = map(int, offset)
        elif fn and sptr.props & idaapi.SF_FRAME:
            base = interface.function.frame_disassembler_offset(fn)
        else:
            base = 0

        # This should be pretty easy, we just need to collect the members matching the
        # slice that we were given. We also stash them so we can return them later.
        selected, lindex, rindex, members, member_references = [], sptr.memqty, 0, {}, {}
        for mowner, mindex, mptr in cls.iterate(sptr, slice):
            lindex, rindex = min(mindex, lindex), max(mindex, rindex)

            # Capture the references for the member so that we can poke
            # the disassembler to update them after we remove the member.
            member_references.setdefault(mptr.id, []).extend(ea for ea, _, _ in interface.xref.to(mptr.id, idaapi.XREF_ALL))

            # If the field is not an important frame member, then add it.
            if mptr.id not in specials:
                members[mptr.soff] = member.packed(base, mptr)
                selected.append((mptr.soff, mptr))
            continue

        # Similar to `remove_bounds`, the members will be shifted which results in the references changing
        # for members following a selected member. Since this is a slice, the results aren't guaranteed to
        # be contiguous. So we recollect everything, but skip over the references that we already got.
        for mowner, mindex, mptr in cls.iterate(sptr, builtins.slice(lindex, None)):
            if mptr.id in member_references:
                continue

            for ea, _, _ in interface.xref.to(mptr.id, idaapi.XREF_ALL):
                member_references.setdefault(mptr.id, []).append(ea)
            continue

        # Clear out any references to special members that were identified.
        [member_references.pop(mid, ()) for mid in specials]

        # Now we need to invert our dictionary of references so that
        # they are keyed by address instead of by the member id.
        references = {}
        for mid, addresses in member_references.items():
            [references.setdefault(ea, []).append(mid) for ea in addresses]
        member_references.clear()

        # Last thing to do is to use the slice to get the indices of the
        # member to remove and reverse them so the numbers don't change.
        indices = sorted(builtins.range(*slice.indices(sptr.memqty)))[::-1]
        iterable = (sptr.members[index] for index in indices)
        listable = [(mptr.id, utils.string.of(idaapi.get_member_fullname(mptr.id)), mptr.soff, idaapi.get_member_size(mptr)) for mptr in iterable if mptr.id not in specials]

        # Now we can ask the disassembler to delete the member at each
        # index specified as a slice. We don't track the delta since
        # the members selected by a slice may not always be contiguous.
        count, failed, is_union = 0, {moffset for moffset in []}, union(sptr)
        for mid, mname, moffset_or_mindex, msize in listable:
            moffset = mindex = moffset_or_mindex
            if moffset_or_mindex not in members:
                continue

            # Go ahead, calculate the description, and then delete the member.
            location_description = "index {:d}".format(mindex) if is_union else "offset {:+#x}".format(moffset + base)
            ok = idaapi.del_struc_member(sptr, mindex if is_union else moffset)

            # Check to see if there's still a member at the offset we deleted. If we couldn't
            # delete it or the member still exists, then we go ahead and complain about it.
            mptr = None if is_union else idaapi.get_member(sptr, moffset)
            if not ok:
                logging.warning(u"{:s}.remove_slice({:#x}, {!s}{:s}) : Unable to remove member \"{:s}\" ({:#x}) at {:s} of the {:s}.".format('.'.join([__name__, cls.__name__]), sptr.id, slice, ", {:+#x}".format(base) if offset else '', utils.string.escape(mname, '"'), mid, location_description, 'union' if union(sptr) else 'frame' if frame(sptr) else 'structure'))
                failed.add((mid, moffset))

            elif mptr:
                logging.warning(u"{:s}.remove_slice({:#x}, {!s}{:s}) : Member \"{:s}\" ({:#x}) at {:s} of {:s} was not removed ({:#x}).".format('.'.join([__name__, cls.__name__]), sptr.id, slice, ", {:+#x}".format(base) if offset else '', utils.string.escape(mname, '"'), mid, location_description, 'union' if union(sptr) else 'frame' if frame(sptr) else 'structure', mptr.id))
                failed.add((mid, moffset))

            # if we succeeded, then we can go ahead and attempt to shrink the structure.
            elif ok and (True if is_union else idaapi.expand_struc(sptr, moffset, -msize)):
                count += 1

            # if we couldn't shrink it, then we avoid updating the size and log a warning.
            else:
                logging.warning(u"{:s}.remove_slice({:#x}, {!s}{:s}) : Unable to remove space ({:d}) {:s} of {:s} after removing member \"{:s}\" ({:#x}).".format('.'.join([__name__, cls.__name__]), sptr.id, slice, ", {:+#x}".format(base) if offset else '', location_description, 'union' if union(sptr) else 'frame' if frame(sptr) else 'structure', utils.string.escape(mname, '"'), mid))
                failed.add((mid, moffset))
            continue

        # If we couldn't remove anything and our results show that
        # we should have, then complain about it and then return.
        if selected and not count:
            logging.fatal(u"{:s}.remove_slice({:#x}, {!s}{:s}) : Unable to remove {:d} member{:s} from the specified {:s} ({:#x}).".format('.'.join([__name__, cls.__name__]), sptr.id, slice, ", {:+#x}".format(base) if offset else '', len(selected), '' if len(selected) == 1 else 's', 'union' if union(sptr) else 'frame' if frame(sptr) else 'structure', sptr.id))
            return []

        # After removing the members, the disassembler doesn't immediately update the
        # cross-references that were changed. Since we collected them earlier, we use
        # them with the best available api to ensure the cross-references get updated.
        if hasattr(idaapi, 'auto_make_step'):
            [idaapi.auto_make_step(ea, idaapi.next_not_tail(ea)) for ea in references]

        elif hasattr(idaapi, 'auto_wait_range'):
            [idaapi.auto_wait_range(ea, idaapi.next_not_tail(ea)) for ea in references]

        # If the number of results matches the number of elements that were deleted,
        # then we're done here and only need to return the members that were removed.
        if len(selected) == count:
            iterable = (members[moffset_or_mindex] for moffset_or_mindex, mptr_deleted in selected if moffset_or_mindex in members)
            iterable = ((mname, mtype, mlocation, mtypeinfo, mcomments) for mid, mname, mtype, mlocation, mtypeinfo, mcomments in iterable)
            return [packed for packed in iterable]

        # Gather all the members that we expected to be able to remove.
        iterable = (moffset_or_mindex for moffset_or_mindex, mptr_deleted in selected)
        iterable = (members[moffset_or_mindex] for moffset_or_mindex in iterable if moffset_or_mindex in members)
        expected = {mid : (mname, mtype, mlocation, mtypeinfo, mcomments) for mid, mname, mtype, mlocation, mtypeinfo, mcomments in iterable}

        # If they didn't, then only some of the members were removed. This makes things
        # a little more complicated and we need to distinguish which members still remain.
        removed, is_union = {mid for mid in []}, union(sptr)
        for moffset_or_mindex, mptr_deleted in selected:
            if moffset_or_mindex not in members:
                continue

            # Grab any information that we need to verify the member doesn't exist.
            mid, mname, _, _, _, _ = members[moffset_or_mindex]
            moffset = mindex = moffset_or_mindex

            # If it still exists (we verify the id), then complain about it.
            mptr = idaapi.get_member(sptr, mindex if is_union else moffset)
            if mptr and mptr.id == mid:
                location_description = "index {:d}".format(mindex) if is_union else "offset {:+#x}".format(moffset + base)
                logging.debug(u"{:s}.remove_slice({:#x}, {!s}{:s}) : Unable to remove member {:s} at {:s} with id ({:#x}) from the specified {:s} ({:#x}).".format('.'.join([__name__, cls.__name__]), sptr.id, slice, ", {:+#x}".format(base) if offset else '', mname, location_description, mid, 'union' if union(sptr) else 'frame' if frame(sptr) else 'structure', sptr.id))
                continue
            removed.add(id)

        # Finally we can complain about the identifers that were not removed,
        # and then proceed to return whatever we were actually able to do.
        logging.warning(u"{:s}.remove_slice({:#x}, {!s}{:s}) : Unable to remove {:d} of {:s} from the specified {:s} ({:#x}).".format('.'.join([__name__, cls.__name__]), sptr.id, slice, ", {:+#x}".format(base) if offset else '', len(expected) - len(removed), "{:d} members".format(len(expected)) if len(expected) == 1 else "the expected {:d} members".format(len(expected)), 'union' if union(sptr) else 'frame' if frame(sptr) else 'structure', sptr.id))

        iterable = (members[moffset] for moffset, mptr_deleted in selected)
        iterable = ((mname, mtype, mlocation, mtypeinfo, mcomments) for mid, mname, mtype, mlocation, mtypeinfo, mcomments in iterable if mid in removed)
        return [packed for packed in iterable]

    @classmethod
    def remove_bounds(cls, sptr, start, stop, *offset):
        '''Remove the members from the offset `start` to `stop` from the structure or union identified by `sptr`.'''
        sptr = idaapi.get_struc(sptr.id if isinstance(sptr, (idaapi.struc_t, structure_t)) else sptr)
        start, stop, size = map(int, [start, stop, idaapi.get_struc_size(sptr)])

        # If the structure is a frame, then there's certain members
        # that we shouldn't delete because it will break the frame.
        ea = idaapi.get_func_by_frame(sptr.id)
        fn = None if ea == idaapi.BADADDR else idaapi.get_func(ea)
        iterable = itertools.chain([idaapi.frame_off_savregs(fn)] if fn.frregs else [], [idaapi.frame_off_retaddr(fn)] if idaapi.get_frame_retsize(fn) else []) if fn else []
        specials = {idaapi.get_member(sptr, moffset).id for moffset in filter(functools.partial(idaapi.get_member, sptr), iterable)}

        # Use the same base the disassembler would use if we weren't given one.
        if offset:
            [base] = map(int, offset)
        elif fn and sptr.props & idaapi.SF_FRAME:
            base = interface.function.frame_disassembler_offset(fn)
        else:
            base = 0

        # Start out by collecting the members that reside within the segment we were
        # given. This is so we can return the removed members when we leave. We also
        # keep track of the indices so that we can figure out later what was removed.
        selected, lindex, rindex, members, references = [], sptr.memqty, 0, {}, {}
        for mowner, mindex, mptr in cls.at_bounds(sptr, start - base, stop - base):
            lindex, rindex = min(mindex, lindex), max(mindex, rindex)

            # Now we can gather the references for the member keyed by their
            # address so that we know which addresses will need to be updated.
            if mptr.id not in specials:
                [references.setdefault(ea, []).append(mptr.id) for ea, _, _ in interface.xref.to(mptr.id, idaapi.XREF_ALL)]

            # Afterwards, as long as it's not a special member, we can add it.
            if mptr.id not in specials:
                members[mptr.soff] = member.packed(base, mptr)
                selected.append((mptr.soff, mptr))
            continue

        # If the structure is not a union, the deletion of elements will shift
        # over every member after the boundaries we were given. So we need to
        # collect references for those members too since they will be affected.
        if not union(sptr):
            for mowner, mindex, mptr in cls.iterate(sptr, slice(rindex, None)):
                for ea, _, _ in interface.xref.to(mptr.id, idaapi.XREF_ALL):
                    references.setdefault(ea, []).append(mptr.id)
                continue

            # Now we can use the indices to figure out the exact boundaries to
            # delete with the disassembler. This also avoids invalid values being
            # passed to the disassembler api. After deleting this range, we preserve
            # the count so that we can complain about it later in case if we failed.
            mleft = sptr.members[lindex] if lindex < sptr.memqty else None
            soff = 0 if mleft and mleft.flag & idaapi.MF_UNIMEM else mleft.soff if mleft else size
            eoff = sptr.members[rindex].eoff if rindex < sptr.memqty else size

            # We now need the indices to remove, but in reverse. This way we can
            # avoid having to do any calcuations for the members that have shifted.
            indices = [mindex for mindex in builtins.range(*slice(lindex, rindex + 1).indices(sptr.memqty))][::-1]
            iterable = (sptr.members[mindex] for mindex in indices)
            listable = [(mptr.id, utils.string.of(idaapi.get_member_fullname(mptr.id)), mptr.soff, idaapi.get_member_size(mptr)) for mptr in iterable if mptr.id not in specials]

        # If we're removing elements from a union, then the work we have to
        # do is simplified since we only need the indices (in reverse) and
        # all deletions or modifications to a union are already destructive.
        else:
            indices = sorted(selected, key=operator.itemgetter(0))
            listable = [(mptr.id, utils.string.of(idaapi.get_member_fullname(mptr.id)), mindex, idaapi.get_member_size(mptr)) for mindex, mptr in indices[::-1] if mptr.id not in specials]

        # Finally we can iterate through everything from the structure, remove
        # an individual member, add some space if necessary, rinse, repeat.
        failed, count, is_union = {moffset for moffset in []}, 0, union(sptr)
        for mid, mname, moffset_or_mindex, msize in listable:
            moffset = mindex = moffset_or_mindex
            if moffset_or_mindex not in members:
                continue

            # Calculate the description of the location and delete the member.
            location_description = "index {:d}".format(mindex) if is_union else "offset {:+#x}".format(moffset + base)
            ok = idaapi.del_struc_member(sptr, mindex if is_union else moffset)

            # If we couldn't delete the member or there's still a member at
            # the offset, then we failed somehow and need to accommodate it.
            mptr = None if is_union else idaapi.get_member(sptr, moffset)
            if not ok:
                logging.warning(u"{:s}.remove_bounds({:#x}, {:#x}, {:#x}{:s}) : Unable to remove member \"{:s}\" ({:#x}) at {:s} of the {:s} ({:#x}).".format('.'.join([__name__, cls.__name__]), sptr.id, start, stop, ", {:+#x}".format(base) if offset else '', utils.string.escape(mname, '"'), mid, location_description, 'union' if union(sptr) else 'frame' if frame(sptr) else 'structure', sptr.id))
                failed.add((mid, moffset))

            elif mptr:
                logging.warning(u"{:s}.remove_bounds({:#x}, {:#x}, {:#x}{:s}) : Member \"{:s}\" ({:#x}) at {:s} of {:s} ({:#x}) was not removed ({:#x}).".format('.'.join([__name__, cls.__name__]), sptr.id, start, stop, ", {:+#x}".format(base) if offset else '', utils.string.escape(mname, '"'), mid, location_description, 'union' if union(sptr) else 'frame' if frame(sptr) else 'structure', sptr.id, mptr.id))
                failed.add((mid, moffset))

            # If we succeeded, then we can go ahead and attempt to shrink the structure.
            elif ok and (True if is_union else idaapi.expand_struc(sptr, moffset, -msize)):
                count += 1

            # If we couldn't shrink it, then we avoid updating the size and log a warning.
            else:
                logging.warning(u"{:s}.remove_bounds({:#x}, {:#x}, {:#x}{:s}) : Unable to remove space ({:d}) at {:s} of {:s} ({:#x}) after removing member \"{:s}\" ({:#x}).".format('.'.join([__name__, cls.__name__]), sptr.id, start, stop, ", {:+#x}".format(base) if offset else '', location_description, 'union' if union(sptr) else 'frame' if frame(sptr) else 'structure', sptr.id, utils.string.escape(mname, '"'), mid))
                failed.add((mid, moffset))
            continue

        # If we removed absolutely nothing (but we were supposed to),
        # then bail here and let the user know that it didn't happen.
        if selected and not count:
            bounds = interface.bounds_t(soff, eoff)
            logging.fatal(u"{:s}.remove_bounds({:#x}, {:#x}, {:#x}{:s}) : Unable to remove {:d} member{:s} within the determined boundaries ({:s}) from the specified {:s} ({:#x}).".format('.'.join([__name__, cls.__name__]), sptr.id, start, stop, ", {:+#x}".format(base) if offset else '', len(selected), '' if len(selected) == 1 else 's', bounds + base, 'union' if union(sptr) else 'frame' if frame(sptr) else 'structure', sptr.id))
            return []

        # We deleted some members, but we might not have deleted all of them. The disassembler
        # hasn't yet updated their references as autoanalysis could be paused. So, we step the
        # autoqueue for every reference we captured with the best api that is available.
        if hasattr(idaapi, 'auto_make_step'):
            [idaapi.auto_make_step(ea, idaapi.next_not_tail(ea)) for ea in references]

        elif hasattr(idaapi, 'auto_wait_range'):
            [idaapi.auto_wait_range(ea, idaapi.next_not_tail(ea)) for ea in references]

        # If our selected count matches, then we're now good and can return our
        # results to the caller. The location for each result is also translated.
        if len(selected) == count:
            iterable = (members[moffset_or_mindex] for moffset_or_mindex, mptr_deleted in selected if moffset_or_mindex in members)
            iterable = ((mname, mtype, mlocation, mtypeinfo, mcomments) for mid, mname, mtype, mlocation, mtypeinfo, mcomments in iterable)
            return [packed for packed in iterable]

        # Collect the members that we had actually expected to have removed.
        iterable = (moffset_or_mindex for moffset_or_mindex, mptr_deleted in selected)
        iterable = (members[moffset_or_mindex] for moffset_or_mindex in iterable if moffset_or_mindex in members)
        expected = {mid : (mname, mtype, mlocation, mtypeinfo, mcomments) for mid, mname, mtype, mlocation, mtypeinfo, mcomments in iterable}

        # Otherwise we only removed some of the members. So, we need
        # to figure out exactly what happened and let the user know.
        removed, is_union = {mid for mid in []}, union(sptr)
        for moffset_or_mindex, mptr_deleted in selected:
            if moffset_or_mindex not in members:
                continue

            # Grab everything we need to check the deleted member and its location.
            mid, mname, _, _, _, _ = members[moffset_or_mindex]
            moffset = mindex = moffset_or_mindex

            # Now we can check the identifier of the member at the deleted location.
            mptr = idaapi.get_member(sptr, mindex if is_union else moffset)
            if mptr and mptr.id == mid:
                location_description = "index {:d}".format(mindex) if is_union else "offset {:+#x}".format(moffset + base)
                logging.debug(u"{:s}.remove_bounds({:#x}, {:#x}, {:#x}{:s}) : Unable to remove member {:s} at {:s} with id ({:#x}) from the specified {:s} ({:#x}).".format('.'.join([__name__, cls.__name__]), sptr.id, start, stop, ", {:+#x}".format(base) if offset else '', mname, location_description, mid, 'union' if union(sptr) else 'frame' if frame(sptr) else 'structure', sptr.id))
                continue
            removed.add(id)

        # We should now have a list of identifiers that were removed. So we only need
        # to proceed with our complaints and return whatever we successfuly deleted.
        bounds = interface.bounds_t(*sorted([start, stop]))
        logging.warning(u"{:s}.remove_bounds({:#x}, {:#x}, {:#x}{:s}) : Unable to remove {:d} of {:s} within the determined boundaries ({:s}) of the specified {:s} ({:#x}).".format('.'.join([__name__, cls.__name__]), sptr.id, start, stop, ", {:+#x}".format(base) if offset else '', len(expected) - len(removed), "{:d} members".format(len(expected)) if len(expected) == 1 else "the expected {:d} members".format(len(expected)), bounds, 'union' if union(sptr) else 'frame' if frame(sptr) else 'structure', sptr.id))

        # Unpack and repack as punishment for such a fucking huge tuple...
        iterable = (members[moffset_or_mindex] for moffset_or_mindex, mptr_deleted in selected if moffset_or_mindex in members)
        iterable = ((mname, mtype, mlocation, mtypeinfo, mcomments) for mid, mname, mtype, mlocation, mtypeinfo, mcomments in iterable if mid in removed)
        return [packed for packed in iterable]

    @classmethod
    def clear_slice(cls, sptr, slice, *offset):
        '''Clear a `slice` of the members belonging to the structure or union identified by `sptr`.'''
        sptr = idaapi.get_struc(sptr.id if isinstance(sptr, (idaapi.struc_t, structure_t)) else sptr)
        slice, size = slice if isinstance(slice, builtins.slice) else builtins.slice(slice, 1 + slice or None), idaapi.get_struc_size(sptr)

        # If our structure is a function frame, then we can't actually touch some of
        # the members. So, we check the frame ahead of time and skip over them later.
        ea = idaapi.get_func_by_frame(sptr.id)
        fn = idaapi.get_func(ea)
        iterable = itertools.chain([idaapi.frame_off_savregs(fn)] if fn.frregs else [], [idaapi.frame_off_retaddr(fn)] if idaapi.get_frame_retsize(fn) else []) if fn else []
        specials = {idaapi.get_member(sptr, moffset).id for moffset in filter(functools.partial(idaapi.get_member, sptr), iterable)}

        # Figure out which offset the disassembler would use if we weren't given one.
        if offset:
            [base] = map(int, offset)
        elif fn and sptr.props & idaapi.SF_FRAME:
            base = interface.function.frame_disassembler_offset(fn)
        else:
            base = 0

        # Just like `remove_slice`, we need to collect the members matching the slice
        # from the parameter. We also stash their references so we can track them.
        selected, lindex, rindex, members, references = [], sptr.memqty, 0, {}, {}
        for mowner, mindex, mptr in cls.iterate(sptr, slice):
            lindex, rindex = min(mindex, lindex), max(mindex, rindex)

            # Capture the references for the member so that we can poke the
            # disassembler to update its references after it gets deleted.
            if mptr.id not in specials:
                [references.setdefault(ea, []).append(mptr.id) for ea, _, _ in interface.xref.to(mptr.id, idaapi.XREF_ALL)]

            # If the field is not a special field, then it's okay to add.
            if mptr.id not in specials:
                members[mptr.soff] = member.packed(base, mptr)
                selected.append((mptr.soff, mptr))
            continue

        # Use our slice parameter to figure out the indices we're being asked
        # to clear. We'll actually be processing these in reverse so that when
        # we remove each member element it won't change the list indexing.
        indices = sorted(builtins.range(*slice.indices(sptr.memqty)))[::-1]
        iterable = (sptr.members[index] for index in indices)
        listable = [(mptr.id, utils.string.of(idaapi.get_member_fullname(mptr.id)), mptr.soff, idaapi.get_member_size(mptr)) for mptr in iterable if mptr.id not in specials]

        # Finally we can just iterate through our list and delete each
        # member that was picked out for us via the slice. We don't need
        # to do anything too special since none of the offsets will change.
        count, failed, is_union = 0, {moffset for moffset in []}, union(sptr)
        for mid, mname, moffset_or_mindex, msize in listable:
            mindex = moffset = moffset_or_mindex
            if moffset_or_mindex not in members:
                continue

            # Now we can build the description and then delete the member that was chosen.
            location_description = "index {:d}".format(mindex) if is_union else "offset {:+#x}".format(moffset + base)
            ok = idaapi.del_struc_member(sptr, mindex if is_union else moffset)

            # Verify that there isn't a member at the offset we just
            # deleted. This way we have a better idea why we failed.
            mptr = None if is_union else idaapi.get_member(sptr, moffset)
            if not ok:
                logging.warning(u"{:s}.clear_slice({:#x}, {!s}{:s}) : Unable to erase member \"{:s}\" ({:#x}) at {:s} of the {:s}.".format('.'.join([__name__, cls.__name__]), sptr.id, slice, ", {:+#x}".format(base) if offset else '', utils.string.escape(mname, '"'), mid, location_description, 'union' if union(sptr) else 'frame' if frame(sptr) else 'structure'))
                failed.add((mid, moffset))

            elif mptr:
                logging.warning(u"{:s}.clear_slice({:#x}, {!s}{:s}) : Member \"{:s}\" ({:#x}) at {:s} of {:s} was not erased ({:#x}).".format('.'.join([__name__, cls.__name__]), sptr.id, slice, ", {:+#x}".format(base) if offset else '', utils.string.escape(mname, '"'), mid, location_description, 'union' if union(sptr) else 'frame' if frame(sptr) else 'structure', mptr.id))
                failed.add((mid, moffset))

            # Otherwise it worked, we're good, it's done.
            else:
                count += 1
            continue

        # If our counter is 0, then we didn't delete anything. If our results
        # tell us that we should've, then log a fatal error and return.
        # we should have, then complain about it and then return.
        if selected and not count:
            logging.fatal(u"{:s}.clear_slice({:#x}, {!s}{:s}) : Unable to erase {:d} member{:s} from the specified {:s} ({:#x}).".format('.'.join([__name__, cls.__name__]), sptr.id, slice, ", {:+#x}".format(base) if offset else '', len(selected), '' if len(selected) == 1 else 's', 'union' if union(sptr) else 'frame' if frame(sptr) else 'structure', sptr.id))
            return []

        # We deleted the members, but if auto-analysis is turned off, then the
        # disassembler hasn't updated the references. If that's the case, we
        # go back and poke the disassembler for each address that had a reference.
        if hasattr(idaapi, 'auto_make_step'):
            [idaapi.auto_make_step(ea, idaapi.next_not_tail(ea)) for ea in references]

        elif hasattr(idaapi, 'auto_wait_range'):
            [idaapi.auto_wait_range(ea, idaapi.next_not_tail(ea)) for ea in references]

        # If our number of results match what we were able to clear,
        # then we only have to return everything that we cleared.
        if len(selected) == count:
            iterable = (members[moffset_or_mindex] for moffset_or_mindex, mptr_deleted in selected if moffset_or_mindex in members)
            iterable = ((mname, mtype, mlocation, mtypeinfo, mcomments) for mid, mname, mtype, mlocation, mtypeinfo, mcomments in iterable)
            return [packed for packed in iterable]

        # Gather everything that we should've been able to remove without issue.
        iterable = (moffset_or_mindex for moffset_or_mindex, mptr_deleted in selected)
        iterable = (members[moffset_or_mindex] for moffset_or_mindex in iterable)
        expected = {mid : (mname, mtype, mlocation, mtypeinfo, mcomments) for mid, mname, mtype, mlocation, mtypeinfo, mcomments in iterable}

        # If we got here, then we weren't able to clear out some of the members. We
        # can't do much other than complain about it, so we drop some logging events.
        deleted, is_union = {mid for mid in []}, union(sptr)
        for moffset_or_mindex, mptr_deleted in selected:
            mid, mname, _, _, _, _ = members[moffset_or_mindex]
            moffset = mindex = moffset_or_mindex

            mptr = idaapi.get_member(sptr, mindex if is_union else moffset)
            if mptr and mptr.id == mid:
                location_description = "index {:d}".format(mindex) if is_union else "offset {:+#x}".format(moffset + base)
                logging.debug(u"{:s}.clear_slice({:#x}, {!s}{:s}) : Unable to erase member {:s} ({:#x}) at {:s} from the specified {:s} ({:#x}).".format('.'.join([__name__, cls.__name__]), sptr.id, slice, ", {:+#x}".format(base) if offset else '', mname, mid, location_description, 'union' if union(sptr) else 'frame' if frame(sptr) else 'structure', sptr.id))
                continue
            deleted.add(id)

        # Finally we can complain about the identifiers that still exist
        # and then proceed to return whatever we were actually able to do.
        logging.warning(u"{:s}.clear_slice({:#x}, {!s}{:s}) : Unable to erase {:d} of {:s} from the specified {:s} ({:#x}).".format('.'.join([__name__, cls.__name__]), sptr.id, slice, ", {:+#x}".format(base) if offset else '', len(expected) - len(deleted), "{:d} members".format(len(expected)) if len(expected) == 1 else "the expected {:d} members".format(len(expected)), 'union' if union(sptr) else 'frame' if frame(sptr) else 'structure', sptr.id))

        iterable = (members[moffset_or_mindex] for moffset_or_mindex, mptr_deleted in selected)
        iterable = ((mname, mtype, mlocation, mtypeinfo, mcomments) for mid, mname, mtype, mlocation, mtypeinfo, mcomments in iterable if mid in removed)
        return [packed for packed in iterable]

    @classmethod
    def clear_bounds(cls, sptr, start, stop, *offset):
        '''Undefine the members from the offset `start` to `stop` in the structure or union identified by `sptr`.'''
        sptr = idaapi.get_struc(sptr.id if isinstance(sptr, (idaapi.struc_t, structure_t)) else sptr)
        start, stop = map(int, [start, stop])

        # If our structure is a function frame, then we can't actually touch some of
        # the members. So, we check the frame ahead of time and skip over them later.
        ea = idaapi.get_func_by_frame(sptr.id)
        fn = idaapi.get_func(ea)
        iterable = itertools.chain([idaapi.frame_off_savregs(fn)] if fn.frregs else [], [idaapi.frame_off_retaddr(fn)] if idaapi.get_frame_retsize(fn) else []) if fn else []
        specials = {idaapi.get_member(sptr, moffset).id for moffset in filter(functools.partial(idaapi.get_member, sptr), iterable)}

        # If the structure is a frame, then figure out the default base offset.
        if offset:
            [base] = map(int, offset)
        elif fn and sptr.props & idaapi.SF_FRAME:
            base = interface.function.frame_disassembler_offset(fn)
        else:
            base = 0

        # Now, just like remove_bounds, we collect all the members that overlap with the
        # segment we were given. This way we can return the cleared members when we leave.
        selected, lindex, rindex, members, references = [], sptr.memqty, 0, {}, {}
        for mowner, mindex, mptr in cls.at_bounds(sptr, start - base, stop - base):
            lindex, rindex = min(mindex, lindex), max(mindex, rindex)

            # Only collect its references if it's a special frame member.
            if mptr.id not in specials:
                references[mptr.soff] = [packed_frm_iscode_type for packed_frm_iscode_type in interface.xref.to(mptr.id, idaapi.XREF_ALL)]

            # If it's not a special field (from a frame), add it to our selection.
            if mptr.id not in specials:
                members[mptr.soff] = member.packed(base, mptr)
                selected.append((mptr.soff, mptr))
            continue

        # If the structure is a union then we can simply remove the member at each
        # index, because there's no way to remove a union member non-descrutively.
        if union(sptr):
            order = sorted(index for index, mptr in selected)

            # Now we need to delete each union member. We do this in reverse order
            # so that when the indices get reordered, our copy will still reference
            # the correct index for the ones that we haven't processed yet.
            results = [(index, idaapi.del_struc_member(sptr, index)) for index in order[::-1]]
            failures = {index for index, success in results if not success}

        # Otherwise we need to cleanly remove each member that was selected. We just iterate
        # through everything, remove a member, add some space if necessary, rinse, repeat.
        else:
            size, failures = idaapi.get_struc_size(sptr), {moffset for moffset in []}
            for moffset, mptr in selected:
                identifier, msize = mptr.id, idaapi.get_member_size(mptr)

                # If we're a special member, then we can just skip processing it.
                if identifier in specials:
                    continue

                # Delete the member. If we did but a member still exists..then the deletion
                # actually failed. This only happens on older versions of the disassembler.
                ok = idaapi.del_struc_member(sptr, moffset)
                if ok and not idaapi.get_member(sptr, moffset):
                    pass

                # We couldn't remove the member at all, which means that we
                # couldn't honor the request the user has made of us.
                else:
                    failures.add(moffset)
                continue

            # We need both the order and failures initialized to proceed.
            order = sorted(moffset for moffset, mptr_deleted in selected)

        # Before we emit any error messages, we need to collect any references to the
        # union/structure that owns the member. This is so we can exclude any xrefs that
        # have been promoted, and only warn about the xrefs that have been truly lost.
        iterable = (packed_frm_iscode_type for moffset, packed_frm_iscode_type in references.items() if moffset not in failures)
        processed = {xfrm for xfrm, _, _ in itertools.chain(*iterable) if idaapi.auto_make_step(xfrm, xfrm + 1)}
        promoted = {xfrm for xfrm, xiscode, xtype in interface.xref.to(sptr.id, idaapi.XREF_ALL)}

        # Now we should have a list of member indices/offsets that were processed, a set of
        # indices/offsets that failed, references, and packed information for the members.
        is_union = union(sptr)
        for moffset_or_mindex, mptr in selected:
            moffset = mindex = moffset_or_mindex
            if moffset_or_mindex not in members:
                continue

            # Unpack some member attributes so that we can reference them in any logs.
            identifier, mname, _, _, _, _ = members[mindex if is_union else moffset]
            location_description = "index {:d}".format(mindex) if is_union else "offset {:+#x}".format(moffset + base)

            # If we were unable to remove a specific member, then log information about
            # the member so that the user knows that something unexpected happened.
            if moffset in failures:
                logging.warning(u"{:s}.clear_bounds({:#x}, {:#x}, {:#x}{:s}) : Unable to remove member \"{:s}\" ({:#x}) that was at {:s} of {:s} ({:#x}).".format('.'.join([__name__, cls.__name__]), sptr.id, start, stop, ", {:#x}".format(base) if offset else '', utils.string.escape(mname, '"'), identifier, location_description, 'union' if union(sptr) else 'frame' if frame(sptr) else 'structure', sptr.id))
                mreferences = []

            # Otherwise, we removed the member and we need to check if any references
            # were lost. We preloaded these, so we just need to format them properly.
            else:
                mreferences = references[moffset]

            # Now we collect our member references into a list of descriptions so that
            # we can let the user know which refs have been lost in the member removal.
            cdrefs = [((None, xfrm) if interface.node.identifier(xfrm) else (xfrm, None)) for xfrm, xiscode, xtype in mreferences if xfrm not in promoted]
            crefs, drefs = ([ea for ea in xrefs if ea is not None] for xrefs in zip(*cdrefs)) if cdrefs else [(), ()]

            # First we do the list of addresses...
            if crefs:
                logging.warning(u"{:s}.clear_bounds({:#x}, {:#x}, {:#x}{:s}) : Removal of member \"{:s}\" ({:#x}) at {:s} has resulted in the removal of {:d} reference{:s} ({:s}).".format('.'.join([__name__, cls.__name__]), sptr.id, start, stop, ", {:#x}".format(base) if offset else '', utils.string.escape(mname, '"'), identifier, location_description, len(crefs), '' if len(crefs) == 1 else 's', ', '.join(map("{:#x}".format, crefs))))

            # ...then we can do the identifiers which includes structures/unions, members, or whatever.
            if drefs:
                logging.warning(u"{:s}.clear_bounds({:#x}, {:#x} {:#x}{:s}) : Removal of member \"{:s}\" ({:#x}) at {:s} has resulted in the removal of {:d} referenced identifier{:s} ({:s}).".format('.'.join([__name__, cls.__name__]), sptr.id, start, stop, ", {:#x}".format(base) if offset else '', utils.string.escape(mname, '"'), identifier, location_description, len(drefs), '' if len(drefs) == 1 else 's', ', '.join(map("{:#x}".format, drefs))))
                [logging.info(u"{:s}.clear_bounds({:#x}, {:#x}, {:#x}{:s}) : Removed member \"{:s}\" ({:#x}) at {:s} used to reference \"{:s}\" ({:#x}).".format('.'.join([__name__, cls.__name__]), sptr.id, start, stop, ", {:#x}".format(base) if offset else '', utils.string.escape(mname, '"'), identifier, location_description, internal.netnode.name.get(idaapi.ea2node(id)), id)) for id in drefs]
            continue

        # Finally we can just return the packed information that we deleted from the structure.
        iterable = ((moffset, members[moffset]) for moffset, _ in selected if moffset in members and moffset not in failures)
        iterable = ((mname, mtype, mlocation, mtypeinfo, mcomments) for moffset, (mid, mname, mtype, mlocation, mtypeinfo, mcomments) in iterable)
        return [(mname, mtype, mlocation, mtypeinfo, mcomments) for mname, mtype, mlocation, mtypeinfo, mcomments in iterable]

    @classmethod
    def layout_getslice(cls, sptr, slice):
        '''Return a contiguous `slice` of the layout belonging to the structure identified by `sptr`.'''
        sptr = idaapi.get_struc(sptr.id if isinstance(sptr, (idaapi.struc_t, structure_t)) else sptr)
        is_variable, is_frame = (sptr.props & prop for prop in [idaapi.SF_VAR, idaapi.SF_FRAME])

        # Figure out the indices for the slice being selected. We will
        # be grabbing the boundaries of the member past these indices
        # so that we can include any empty space within the selection.
        slice = slice if isinstance(slice, builtins.slice) else builtins.slice(slice, 1 + slice or None)
        istart, istop, istep = slice.indices(sptr.memqty)
        listable = [(mowner, mindex, mptr) for mowner, mindex, mptr in cls.iterate(sptr, slice)]
        indices, selected = zip(*((mindex, mptr) for mowner, mindex, mptr in listable)) if listable else ([], [])

        # If the structure is a union, then our slice doesn't need to be
        # contiguous. So we can simply include the index and return it.
        if union(sptr):
            sizes = [idaapi.get_member_size(mptr) for mptr in selected]
            return min(sizes), max(sizes), [(mptr.soff, mptr) for mptr in selected]

        # Otherwise, we need to figure out the start and end offsets.
        if istart < istop:
            ileft, iright = istart, istop
            soff = 0 if ileft < 0 or slice.start is None else sptr.members[ileft].soff if ileft < sptr.memqty else idaapi.get_struc_size(sptr)
            eoff = idaapi.get_struc_size(sptr) if sptr.memqty <= iright or slice.stop is None else 0 if iright < 0 else sptr.members[iright].soff

        elif istart > istop:
            ileft, iright = istop, istart
            soff = 0 if ileft < 0 or slice.stop is None else sptr.members[ileft].eoff if ileft < sptr.memqty else idaapi.get_struc_size(sptr)
            eoff = idaapi.get_struc_size(sptr) if sptr.memqty <= iright or slice.start is None else 0 if iright < 0 else sptr.members[iright].soff

        # If the start and end indices are the same, and something was
        # selected, then use the boundaries for the selected member.
        elif indices:
            soff, eoff = sptr.members[istart].soff, sptr.members[istop].eoff

        # Otherwise nothing was selected, which makes this sort of
        # like selecting a single point within the list of members.
        else:
            index = min(istart, istop)
            point = 0 if index < 0 else sptr.members[index].soff if index < sptr.memqty else idaapi.get_struc_size(sptr)
            soff = 0 if slice.start is None else point
            eoff = idaapi.get_struc_size(sptr) if slice.stop is None else point

        # Store the unique points (sorted) with the segments from the selection.
        iterable = itertools.chain(*([mptr.soff, mptr.eoff] for mptr in selected))
        points = [point for point, duplicates in itertools.groupby(sorted(iterable))]

        # Add the boundary points to our list that we figured out from the selection.
        points.insert(0, soff) if any([not points, points and operator.lt(soff, *points[:+1])]) else points
        points.append(eoff) if any([not points, points and operator.gt(eoff, *points[-1:])]) else points

        # Iterate through the members and add each one to its corresponding segment.
        segments, iterable = {}, ((mptr, mptr.soff, mptr.eoff) for mptr in selected)
        for mptr, mstart, mstop in sorted(iterable, key=operator.itemgetter(1)):
            start, stop = mstart, mstop if mstart < mstop else mstop + member.element(mptr) if is_variable and mstart == mstop else mstop
            segments[mstart] = segments[mstop] = mptr

        # If our selection is from left to right (ordered), then we treat it as
        # normal and be sure to include the empty space in front of the last member.
        if selected and istart <= istop:
            imaximum = 1 + max(indices) if indices else 0
            maximum = sptr.members[imaximum].soff if imaximum < sptr.memqty else points[-1]
            start = bisect.bisect_left(points, points[0] if slice.start is None else selected[0].soff)
            stop = bisect.bisect_left(points, points[-1] if slice.stop is None else maximum) + 1

        # If the selection is from right to left (reversed), then we need to
        # invert our tests against the slice and adjust for the minimum point.
        elif selected:
            iminimum = min(istart, istop)
            minimum = sptr.members[iminimum].eoff if iminimum > 0 else points[0]
            start = bisect.bisect_left(points, points[0] if slice.stop is None else minimum)
            stop = bisect.bisect_left(points, points[-1] if slice.start is None else selected[0].eoff)

        # If we couldn't select anything, then use the boundaries of the
        # members that were within the requested slice to identify the points.
        elif sptr.memqty:
            sleft, sright = (slice.start, slice.stop) if istart <= istop else (slice.stop, slice.start)
            iterable = ((sptr.members[index].soff if index < sptr.memqty else eoff) for index in [istart, istop])
            minimum = min(points) if sleft is None else min(*iterable)
            iterable = ((sptr.members[index].eoff if index < sptr.memqty else eoff) for index in [istart, istop])
            maximum = max(points) if sright is None else max(*iterable)
            start = bisect.bisect_left(points, minimum)
            stop = bisect.bisect_left(points, maximum) + 1 if istart <= istop else bisect.bisect_left(points, maximum)

        # Otherwise since there's no selection or even members, we have nothing to return.
        else:
            return soff, eoff, []

        # Now we need to figure out which direction to slice the elements in.
        step, point = -1 if istep < 0 else +1, 0 if start < 0 else points[start] if start < len(points) else eoff

        # Last thing to do is to iterate through each point to yield each member and
        # any holes. Each member should only be yielded once, so we track that too.
        offset, result, available = point, [], {mptr.id : mptr for mptr in selected}
        for point in points[start : stop]:
            if offset < point:
                result.append((offset, point - offset))
            mptr = segments.get(point, None)
            if mptr and mptr.id in available:
                result.append((point, available.pop(mptr.id)))
            offset = mptr.eoff if mptr else point

        # Verify that the slice we were given is able to select something.
        if not any([istart <= istop and istep > 0, istart > istop and istep < 0]) and not available:
            return points[start], point, []
        return points[start], point, result[::-1 if istep < 0 else +1]

    @classmethod
    def layout_setslice(cls, sptr, slice, layout, *offset):
        '''Update the contigious `slice` belonging to the structure identified by `sptr` with the specified `layout`.'''
        sptr = idaapi.get_struc(sptr.id if isinstance(sptr, (idaapi.struc_t, structure_t)) else sptr)
        is_variable, is_frame = (sptr.props & prop for prop in [idaapi.SF_VAR, idaapi.SF_FRAME])

        # Check if we're acting on a function frame and gets the function
        # if so. We also calculate the base offset if we weren't given one.
        ea = idaapi.get_func_by_frame(sptr.id)
        fn = idaapi.get_func(ea)
        [base] = map(int, offset) if offset else [interface.function.frame_disassembler_offset(fn) if fn and is_frame else 0]

        # Assign some constants and build some descriptions to help with logging.
        FF_STRUCT = idaapi.FF_STRUCT if hasattr(idaapi, 'FF_STRUCT') else idaapi.FF_STRU
        slice_description = "{!s}".format(slice)
        offset_description = ", {:#x}".format(base) if offset else ''

        # First we need to validate our parameters to ensure we were given
        # a slice if we are being asked to assign with some kind of iterable.
        multiple = isinstance(layout, types.ordered) and not isinstance(layout, interface.namedtypedtuple)
        if multiple and not isinstance(slice, builtins.slice):
            iterable = interface.contiguous.describe(layout if multiple else [layout])
            raise E.InvalidParameterError(u"{:s}.layout_setslice({:#x}, {!s}, {:s}{:s}) : Unable to assign a non-iterable to a slice ({!s}) for the specified {:s} ({:#x}).".format('.'.join([__name__, cls.__name__]), sptr.id, slice_description, "[{:s}]".format(', '.join(iterable)), offset_description, slice_description, 'union' if union(sptr) else 'frame' if frame(sptr) else 'structure', sptr.id))

        # Now we can order our layout as a list and then use the slice
        # to select all of the contiguous we're being asked to assign to.
        iterable = layout if multiple else [layout]
        newlayout = [item for item in iterable]
        layout_description = "[{:s}]".format(', '.join(interface.contiguous.describe(newlayout)))
        left, right, selected = cls.layout_getslice(sptr, slice)

        # If our structure is a function frame, then certain members cannot be replaced.
        special = idaapi.get_member(sptr, idaapi.frame_off_retaddr(fn)) if fn and idaapi.get_frame_retsize(fn) and selected else None
        if special and any(special.id == mptr.id for _, mptr in selected if isinstance(mptr, idaapi.member_t)):
            midx, mname = next(idx for idx in range(sptr.memqty) if sptr.members[idx].id == special.id), member.get_name(special)
            raise E.InvalidParameterError(u"{:s}.layout_setslice({:#x}, {!s}, {:s}{:s}) : Unable to replace the special member \"{:s}\" at index {:d} of the frame belonging to function {:#x}.".format('.'.join([__name__, cls.__name__]), sptr.id, slice_description, layout_description, offset_description, mname, midx, ea))

        # Since our assignment will be destructive, we need to calculate the
        # original size and the new size before figuring out how to assign things.
        iterable = (mptr for offset, mptr in selected)
        oldsize, newsize = (interface.contiguous.size(members) for members in [iterable, newlayout])

        # Next since we want to confirm any references that get destroyed, we
        # collect all references to any of the members that were selected.
        iterable = ((offset, mptr, interface.xref.to(mptr.id, idaapi.XREF_ALL)) for offset, mptr in selected if isinstance(mptr, idaapi.member_t))
        references = {offset : (mptr.id, [packed_frm_iscode_type for packed_frm_iscode_type in refs]) for offset, mptr, refs in iterable}
        references[idaapi.get_struc_size(sptr.id)] = sptr.id, [packed_frm_iscode_type for packed_frm_iscode_type in interface.xref.to(sptr.id, idaapi.XREF_ALL)]

        # Before we do any serious damage to the union/structure, save the
        # selected member data that we plan on overwriting with our new layout.
        iterable = ((offset, mptr) for offset, mptr in selected if isinstance(mptr, idaapi.member_t))
        olditems = {offset : member.packed(base, mptr) for offset, mptr in iterable}

        # Now we can lay out each member that we're going to assign contiguously
        # and collect each offset along with their minimum attributes into a list.
        newitems, area_t = [], idaapi.area_t if idaapi.__version__ < 7.0 else idaapi.range_t
        iterable = interface.contiguous.layout(left, newlayout, +1)
        layout = ((sptr.memqty + idx, item) for idx, (_, item) in enumerate(iterable)) if union(sptr) else iterable
        for offset, item in layout:
            if isinstance(item, (types.integer, interface.bounds_t, area_t, interface.namedtypedtuple, interface.symbol_t)):
                msize = interface.range.size(item) if isinstance(item, area_t) else item.size if hasattr(item, 'size') else item
                assert(isinstance(msize, types.integer)), u"{:s}.layout_setslice({:#x}, {!s}, {:s}{:s}) : Unable to determine member size ({!r}) for an unsupported type {!s} ({!r}).".format('.'.join([__name__, cls.__name__]), sptr.id, slice_description, layout_description, offset_description, msize, item.__class__, item)
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
                    raise E.InvalidTypeOrValueError(u"{:s}.layout_setslice({:#x}, {!s}, {:s}{:s}) : Unable to parse the given string (\"{:s}\") into a valid type.".format('.'.join([__name__, cls.__name__]), sptr.id, slice_description, layout_description, offset_description, utils.string.escape("{!s}".format(item), '"')))
                mptr = item

            # If it's pythonic and we can get a non-zero size, then preserve it for later.
            elif interface.typemap.size(item):
                mptr = item

            # Anything else, we have no idea how to handle and so we can just bail here.
            else:
                raise E.InvalidTypeOrValueError(u"{:s}.layout_setslice({:#x}, {!s}, {:s}{:s}) : Unable to determine member attributes for an unsupported type {!s} ({!r}).".format('.'.join([__name__, cls.__name__]), sptr.id, slice_description, layout_description, offset_description, item.__class__, item))

            # Now we can add the member and offset, but we first need to validate it
            # in that we can't add the same structure to itself. We need to capture
            # its flag, opinfo, bytes, and other stuff so that we can add it as a member.
            if isinstance(mptr, idaapi.struc_t):
                opinfo, nbytes = idaapi.opinfo_t(), idaapi.get_struc_size(mptr)
                if mptr.id == sptr.id:
                    logging.warning(u"{:s}.layout_setslice({:#x}, {!s}, {:s}{:s}) : Trying to assign a {:s} ({:#x}) to itself at {:s} will result in an empty member of {:d} byte{:s}.".format('.'.join([__name__, cls.__name__]), sptr.id, slice_description, layout_description, offset_description, 'union' if union(sptr) else 'frame' if frame(sptr) else 'structure', mptr.id, "index {:d}".format(offset) if union(sptr) else "offset {:#x}".format(base + offset), nbytes, '' if nbytes == 1 else 's'))
                opinfo.tid = mptr.id

                # We were given a structure, so we just need to get the type and the correct flags.
                tinfo = None if mptr.id == sptr.id else address.type(mptr.id)
                flag = idaapi.struflag() if idaapi.__version__ < 7.0 else idaapi.stru_flag()

                # Copy any repeatable comment from the structure as a non-repeatable comment.
                cmt = idaapi.get_struc_cmt(mptr.id, True)
                comments = [utils.string.of(cmt)]   # index 0 (false) is non-repeatable.

            # Make an exact copy of the member information, comments, type information, and all.
            elif isinstance(mptr, idaapi.member_t):
                nbytes, tinfo, opinfo = idaapi.get_member_size(mptr), member.get_typeinfo(mptr), idaapi.opinfo_t()
                flag, res = mptr.flag, idaapi.retrieve_member_info(mptr, opinfo) if idaapi.__version__ < 7.0 else idaapi.retrieve_member_info(opinfo, mptr)
                opinfo = opinfo if res else None

                # Extract the comments in order...index 0 (false) is non-repeatable, index 1 (true) is repeatable.
                comments = [utils.string.of(idaapi.get_member_cmt(mptr.id, repeatable)) for repeatable in [False, True]]

            # If we received a type or a string, then we'll need to determine
            # the flags so that we can properly assign it into the structure.
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

            # If it's an integer, then this is just a size and nothing else.
            else:
                opinfo, flag, nbytes, tinfo, comments = None, 0, mptr, None, []

            # Pack all of the member information so that we can add the information later,
            # and verify the size to ensure we aren't trying to add a variable-sized member.
            packed = opinfo, flag, nbytes, tinfo, comments
            if nbytes:
                newitems.append((offset, mptr, packed))
            else:
                logging.warning(u"{:s}.layout_setslice({:#x}, {!s}, {:s}{:s}) : Skipping the addition of member at {:s} of {:s} due to not having a valid size ({:d}).".format('.'.join([__name__, cls.__name__]), sptr.id, slice_description, layout_description, offset_description, "index {:d}".format(offset) if union(sptr) else "offset {:#x}".format(base + offset), 'union' if union(sptr) else 'frame' if frame(sptr) else 'structure', nbytes))
            continue

        # In order to ensure that there aren't any errors when assigning members, we need to
        # confirm that any new members will not have a duplicate name. This can happen when
        # expanding or shrinking a structure without adjusting the names or if the user
        # explicitly specified a name already being used. So, we need to go through all of the
        # newitems and figure out if any will end up being duplicated. We accomplish this in
        # multiple passes. We start with the first pass to gather the potential default names.
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

        # The second pass requires us to go through each of the new items and
        # extract each name into a dictionary of candidate names. These will
        # overwrite any of the default names that were determined in the first pass.
        original, candidates = {}, {}
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
            # integer. If it's not an integer, then we ensure it gets a name.
            elif not isinstance(mptr, types.integer):
                mname = member.default_name(sptr, None, offset)
                original[offset] = newnames[offset] = mname
                candidates.setdefault(mname, []).append(offset)
            continue

        # To avoid iterating through all the names within our structure (which
        # may be large), we now re-format all of our candidate names into "full"
        # structure member names. This way we can ask the disassembler if the
        # name is already being used and we only need to process as much data
        # as the number of members that we're being asked to assign to the slice.
        sname = internal.netnode.name.get(idaapi.ea2node(sptr.id))

        # Now that we have all the candidate names, we start by figuring out which of our
        # names are duplicates that we can't use. Any candidate name that is associated
        # with more than one member offset is a duplicate name in the fields being added.
        iterable = ((mname, offsets, idaapi.get_member_by_name(sptr, utils.string.to(mname))) for mname, offsets in candidates.items())
        duplicates = {mname : offsets for mname, offsets, mptr in iterable if len(offsets) > 1 or mptr}

        # Last thing we need is a way to calculate the real offset for a member.
        frargs = idaapi.frame_off_args(fn) if fn else 0
        #calculate_offset = functools.partial(idaapi.soff_to_fpoff, fn)     # XXX: this can calculate fpoff incorrectly if the fpd is busted
        calculate_offset = lambda moff: offset - frargs if frargs <= offset else offset - fn.frsize
        delta = newsize - oldsize

        # Now we can go through the list of duplicates, calculate a unique
        # name for the member, and then add it to the newnames dictionary.
        for mname, offsets in duplicates.items():
            for offset in offsets:
                oldname = newnames[offset]
                assert(oldname == mname)

                # If the member name already exists and it's being used by the current member,
                # then we don't need to fix the name. We only need to adjust the members after
                # our slice since we treat all structures as if they're growing downwards.
                mptr = idaapi.get_member_by_name(sptr, utils.string.to(oldname))
                oldoffset = mptr.soff + delta if mptr.soff >= right else mptr.soff
                if mptr and oldoffset == offset:
                    continue

                # Now we attempt to calculate the new name if a duplicate one was found. We
                # continue to suffix the member offset until the name is finally "unique".
                name, adjusted = mname, calculate_offset(offset) if fn else offset
                while name in candidates or idaapi.get_member_by_name(sptr, utils.string.to(name)):
                    name = '_'.join([name, "{:X}".format(abs(adjusted))])
                newname = name

                # Update our newnames dictionar with the new name that we generated.
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
                logging.warning(u"{:s}.layout_setslice({:#x}, {!s}, {:s}{:s}) : Using alternative name \"{:s}\" for new member at {:s} of {:s} ({:#x}) as the member ({:#x}) at {:s} is currently using the requested name \"{:s}\".".format('.'.join([__name__, cls.__name__]), sptr.id, slice_description, layout_description, offset_description, utils.string.escape(newname, '"'), new_descr, 'union' if union(sptr) else 'frame' if frame(sptr) else 'structure', sptr.id, mptr.id, old_descr, utils.string.escape(oldname, '"')))

            elif isinstance(mptr, (idaapi.tinfo_t, types.string)):
                conflict = idaapi.get_member_by_name(sptr, utils.string.to(oldname))
                new_descr = "index {:d}".format(offset) if union(sptr) else "offset {:+#x}".format(base + offset)
                old_descr = "member ({:#x}) at {:s} is currently using the requested name \"{:s}\"".format(conflict.id, "index {:d}".format(conflict.soff) if union(sptr) else "offset {:+#x}".format(base + conflict.soff), utils.string.escape(oldname, '"')) if conflict else "original name \"{:s}\" is currenty being used".format(utils.string.escape(oldname, '"'))
                logging.warning(u"{:s}.layout_setslice({:#x}, {!s}, {:s}{:s}) : Using alternative name \"{:s}\" for new member at {:s} of {:s} ({:#x}) as the {:s}.".format('.'.join([__name__, cls.__name__]), sptr.id, slice_description, layout_description, offset_description, utils.string.escape(newname, '"'), new_descr, 'union' if union(sptr) else 'frame' if frame(sptr) else 'structure', sptr.id, old_descr))

            elif not isinstance(mptr, types.integer):
                conflict = idaapi.get_member_by_name(sptr, utils.string.to(oldname))
                new_descr = "index {:d}".format(offset) if union(sptr) else "offset {:+#x}".format(base + offset)
                old_descr = "member ({:#x}) at {:s} is currently using the requested name \"{:s}\"".format(conflict.id, "index {:d}".format(conflict.soff) if union(sptr) else "offset {:+#x}".format(base + conflict.soff), utils.string.escape(oldname, '"')) if conflict else "original name \"{:s}\" is currenty being used".format(utils.string.escape(oldname, '"'))
                logging.warning(u"{:s}.layout_setslice({:#x}, {!s}, {:s}{:s}) : Using alternative name \"{:s}\" for new member at {:s} of {:s} ({:#x}) as the {:s}.".format('.'.join([__name__, cls.__name__]), sptr.id, slice_description, layout_description, offset_description, utils.string.escape(newname, '"'), new_descr, 'union' if union(sptr) else 'frame' if frame(sptr) else 'structure', sptr.id, old_descr))
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
                    logging.warning(u"{:s}.layout_setslice({:#x}, {!s}, {:s}{:s}) : The {:s} owning the member ({:#x}) at {:s} that is attempting to be removed does not actually belong to us and may result in fatal error.".format('.'.join([__name__, cls.__name__]), sptr.id, slice_description, layout_description, offset_description, 'union' if union(sptr) else 'frame' if frame(sptr) else 'structure', mptr.id, "index {:d}".format(mptr.soff) if union(sptr) else "offset {:+#x}".format(base + offset)))

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
                    logging.critical(u"{:s}.layout_setslice({:#x}, {!s}, {:s}{:s}) : Unable to remove the selected member ({:#x}) from {:s} of {:s} for replacement.".format('.'.join([__name__, cls.__name__]), sptr.id, slice_description, layout_description, offset_description, mptr.id, "index {:d}".format(mptr.soff) if union(sptr) else "offset {:+#x}".format(base + offset), 'union' if union(sptr) else 'frame' if frame(sptr) else 'structure'))
                continue

        # If we didn't remove all of the items that we expected, then we should prolly bail.
        # FIXME: We should probably revert and restore the olditems that we've already partially removed.
        if count != len(olditems):
            raise E.DisassemblerError(u"{:s}.layout_setslice({:#x}, {!s}, {:s}{:s}) : Expected to remove {:d} member{:s}, but {:d} were removed.".format('.'.join([__name__, cls.__name__]), sptr.id, slice_description, layout_description, offset_description, len(olditems), '' if len(olditems) == 1 else 's', count))

        # Now we need to figure out whether we're growing the structure, or shrinking it.
        size, delta = idaapi.get_struc_size(sptr), 0 if union(sptr) else newsize - oldsize
        if delta and left < size and not idaapi.expand_struc(sptr, left, delta):
            raise E.DisassemblerError(u"{:s}.layout_setslice({:#x}, {!s}, {:s}{:s}) : Unable to {:s} the size of the structure by {:d} byte{:s} at offset {:+#x}.".format('.'.join([__name__, cls.__name__]), sptr.id, slice_description, layout_description, offset_description, 'decrease' if delta < 0 else 'increase', abs(delta), '' if abs(delta) == 1 else 's', left))

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
                logging.debug(u"{:s}.layout_setslice({:#x}, {!s}, {:s}{:s}) : Skipping {!r} byte{:s} of space at {:s} of {:s}.".format('.'.join([__name__, cls.__name__]), sptr.id, slice_description, layout_description, offset_description, nbytes, '' if nbytes == 1 else 's', "index {:d}".format(offset) if union(sptr) else "offset {:+#x}".format(base + offset), 'union' if union(sptr) else 'frame' if frame(sptr) else 'structure'))
                err, position = idaapi.STRUC_ERROR_MEMBER_OK, offset

            # Otherwise add it using the attributes that were packed into newitems.
            else:
                position = sptr.memqty if union(sptr) else offset
                logging.debug(u"{:s}.layout_setslice({:#x}, {!s}, {:s}{:s}) : Adding member at {:s} as {:d} byte{:s} of space with the specified flags ({:#x}).".format('.'.join([__name__, cls.__name__]), sptr.id, slice_description, layout_description, offset_description, "index {:d}".format(offset) if union(sptr) else "offset {:+#x}".format(base + offset), nbytes, '' if nbytes == 1 else 's', flag))
                err = idaapi.add_struc_member(sptr, utils.string.to(newnames[offset]), idaapi.BADADDR if union(sptr) else position, flag, opinfo, nbytes)

            # Immediately rip the identifier out of the member if we were able to add it to the
            # structure/union succesfully. Apparently, the mptr (member_t) can completely go out
            # of scope for no good reason (whatsoever) while we're processing the new items list.
            if err == idaapi.STRUC_ERROR_MEMBER_OK:
                mptr = idaapi.get_member(sptr, position)
                if err == idaapi.STRUC_ERROR_MEMBER_OK and mptr:
                    results.append((position, mptr.id, packed))
                continue

            # Check to see if we encountered an error of some sort while trying to add the member.
            error_description = {}
            error_description[idaapi.STRUC_ERROR_MEMBER_NAME] = 'a duplicate field name', "\"{:s}\"".format(utils.string.escape(newnames[offset], '"'))
            error_description[idaapi.STRUC_ERROR_MEMBER_OFFSET] = 'an invalid offset', "{:+#x}".format(offset)
            error_description[idaapi.STRUC_ERROR_MEMBER_SIZE] = 'an invalid field size', "{:d}".format(nbytes)
            error_description[idaapi.STRUC_ERROR_MEMBER_TINFO] = 'an invalid type id', "{:#x}".format(opinfo.tid if opinfo else idaapi.BADADDR)
            error_description[idaapi.STRUC_ERROR_MEMBER_STRUCT] = 'a bad structure identifier', "{:#x}".format(sptr.id)

            if err in error_description:
                reason, culprit = error_description[err]
                logging.warning(u"{:s}.layout_setslice({:#x}, {!s}, {:s}{:s}) : Error ({:d}) adding member at {:s} of {:s} ({:#x}) due to {:s} ({:s}).".format('.'.join([__name__, cls.__name__]), sptr.id, slice_description, layout_description, offset_description, err, "index {:d}".format(offset) if union(sptr) else "offset {:+#x}".format(base + offset), 'union' if union(sptr) else 'frame' if frame(sptr) else 'structure', sptr.id, reason, culprit))
            else:
                logging.warning(u"{:s}.layout_setslice({:#x}, {!s}, {:s}{:s}) : Error ({:d}) while adding member at {:s} of {:s} ({:#x}).".format('.'.join([__name__, cls.__name__]), sptr.id, slice_description, layout_description, offset_description, err, "index {:d}".format(offset) if union(sptr) else "offset {:+#x}".format(base + offset), 'union' if union(sptr) else 'frame' if frame(sptr) else 'structure', sptr.id))
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
                logging.warning(u"{:s}.layout_setslice({:#x}, {!s}, {:s}{:s}) : Skipping the application of type information for the member ({:#x}) at {:s} due to its identifier being invalid.".format('.'.join([__name__, cls.__name__]), sptr.id, slice_description, layout_description, offset_description, id, "index {:d}".format(offset) if union(sptr) else "offset {:+#x}".format(base + offset)))
                continue

            # If the member doesn't belong to our structure/union at all, then ignore it and move on.
            if owner.id != sptr.id:
                logging.warning(u"{:s}.layout_setslice({:#x}, {!s}, {:s}{:s}) : The {:s} owning the member ({:#x}) at {:s} that is attempting to be removed does not actually belong to us ({:#x}) and will not have its type information copied.".format('.'.join([__name__, cls.__name__]), sptr.id, slice_description, layout_description, offset_description, 'union' if union(owner) else 'frame' if frame(owner) else 'structure', mptr.id, "index {:d}".format(mptr.soff) if union(sptr) else "offset {:+#x}".format(base + offset), sptr.id))
                continue

            # Apply any type information that we were able to snag to the newly created member.
            # XXX: we should catch any exceptions raised here so that we don't interrupt the
            #      application of type information and other metadata to any missed members.
            if opinfo is not None and tinfo and tinfo.get_size() != idaapi.BADSIZE:
                member.set_typeinfo(mptr, tinfo)

            # Apply any comments that we might've needed to copy.
            for repeatable, string in enumerate(comments):
                if string and not idaapi.set_member_cmt(mptr, utils.string.to(string), repeatable):
                    logging.debug(u"{:s}.layout_setslice({:#x}, {!s}, {:s}{:s}) : Unable to update member ({:s}) at {:s} of {:s} ({:#x}) with {:s} comment \"{:s}\".".format('.'.join([__name__, cls.__name__]), sptr.id, slice_description, layout_description, offset_description, mptr.id, "index {:d}".format(offset) if union(sptr) else "offset {:+#x}".format(base + offset), 'union' if union(sptr) else 'frame' if frame(sptr) else 'structure', sptr.id, 'repeatable' if repeatable else 'non-repeatable', utils.string.escape(string, '"')))
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
        oldmembers = {id : (name, offset) for offset, (id, name, _, location, _, _) in olditems.items()}
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

        # Now we can just take a union of the old and the new references
        # to figure out what has just transpired with regards to them.
        oldrefs, newrefs = ({ea for ea in refs} for refs in [old, new])
        for ea in oldrefs & newrefs:
            assert(new[ea])
            old_ea = old[ea]
            for new_ea in new[ea]:
                olditem, newitem = oldmembers[old[ea]], newmembers[new_ea]
                newname, newoffset = newitem
                oldname, oldoffset = olditem
                old_descr, new_descr = ("structure \"{:s}\"".format(utils.string.escape(name, '"')) if id == sptr.id else "field \"{:s}\" ({:+#x})".format(utils.string.escape(name, '"'), offset) for id, offset, name in zip([old_ea, new_ea], [oldoffset, newoffset], [oldname, newname]))
                logging.info(u"{:s}.layout_setslice({:#x}, {!s}, {:s}{:s}) : Reference at address {:#x} has moved from {:s} to new {:s}.".format('.'.join([__name__, cls.__name__]), sptr.id, slice_description, layout_description, offset_description, ea, old_descr, new_descr))
            continue

        # Any old references that aren't in the new references have been lost. This
        # should actually never happen if the disassembler is working properly.
        for ea in oldrefs - newrefs:
            old_ea = old[ea]
            oldname, oldoffset = oldmembers[old[ea]]
            logging.warning(u"{:s}.layout_setslice({:#x}, {!s}, {:s}{:s}) : Reference at address {:#x} that was referencing {:s} \"{:s}\" ({:+#x}) was lost during assignment.".format('.'.join([__name__, cls.__name__]), sptr.id, slice_description, layout_description, offset_description, ea, 'structure' if old_ea == sptr.id else 'field', utils.string.escape(oldname, '"'), oldoffset))

        # Finally we can return everything that we've just removed back to the caller.
        iterable = (olditems[offset] for offset, _ in selected if offset in olditems)
        return [(mname, mtype, mlocation, mtypeinfo, mcomments) for mid, mname, mtype, mlocation, mtypeinfo, mcomments in iterable]

    @classmethod
    def format_error_add_member(cls, code):
        '''Return the specified error `code` as a tuple composed of the error name and its description.'''
        descriptions, names = {}, {getattr(idaapi, attribute) : attribute for attribute in dir(idaapi) if attribute.startswith('STRUC_ERROR_MEMBER_')}
        descriptions[idaapi.STRUC_ERROR_MEMBER_OK] = 'success'
        descriptions[idaapi.STRUC_ERROR_MEMBER_NAME] = 'duplicate field name'
        descriptions[idaapi.STRUC_ERROR_MEMBER_OFFSET] = 'specified offset already contains a member'
        descriptions[idaapi.STRUC_ERROR_MEMBER_SIZE] = 'invalid number of bytes'
        descriptions[idaapi.STRUC_ERROR_MEMBER_TINFO] = 'invalid type identifier'
        descriptions[idaapi.STRUC_ERROR_MEMBER_STRUCT] = 'invalid structure identifier'
        descriptions[idaapi.STRUC_ERROR_MEMBER_UNIVAR] = 'unions cannot contain a variable sized member'
        descriptions[idaapi.STRUC_ERROR_MEMBER_VARLAST] = 'unable to add a variable sized member at this offset'
        descriptions[idaapi.STRUC_ERROR_MEMBER_NESTED] = 'unable to recursively nest a structure'
        return names.get(code, ''), descriptions.get(code, '')

    @classmethod
    def add(cls, sptr, name, type, location, *offset):
        '''Add a member to the structure identified by `sptr` with the given `name`, `type`, and `location`.'''
        sptr = idaapi.get_struc(sptr.id if isinstance(sptr, (idaapi.struc_t, structure_t)) else sptr)
        set_member_tinfo = idaapi.set_member_tinfo2 if idaapi.__version__ < 7.0 else idaapi.set_member_tinfo

        # First, we need to figure out the base offset in order to make sense of
        # the location. So, we grab the function and unpack the base if available.
        ea = idaapi.get_func_by_frame(sptr.id)
        fn = idaapi.get_func(ea)
        [base] = map(int, offset) if offset else [interface.function.frame_disassembler_offset(fn) if fn and sptr.props & idaapi.SF_FRAME else 0]
        offset_description = ", {:#x}".format(base) if offset else ''

        # Now we need to make sense of the location we were given. This
        # is because the structure can also be a frame or a union, and
        # so we'll need to translate it to the real structure offset.
        is_union, is_frame, is_variable = union(sptr), sptr.props & idaapi.SF_FRAME, sptr.props & idaapi.SF_VAR

        index_or_offset = useroffset = int(location)
        userindex = realoffset = index_or_offset if is_union else index_or_offset - base
        realindex = userindex if userindex <= sptr.memqty else sptr.memqty
        location_description = "{:d}".format(userindex) if is_union else "{:#x}".format(useroffset)

        # Next we need to figure out the name. Similar to all names, the name is
        # "packed" so that adding a numeric suffix avoids a string concatenation.
        packedname = interface.tuplename(*name) if isinstance(name, types.ordered) else name or ''
        defaultname = member.default_name(sptr, None, realindex if is_union else realoffset)
        suffix = realindex if is_union else interface.function.frame_member_offset(fn, realoffset) if is_frame else useroffset
        name_description = "{!s}".format(tuple(name)) if isinstance(name, types.ordered) else "{!r}".format(name)

        # However, we need to check if the name is valid to determine if we need
        # to add a suffix, or use a default name for the field if we didn't get one.
        oldname = candidatename = packedname or defaultname
        while idaapi.get_member_by_name(sptr, utils.string.to(candidatename)):
            candidatename = "{:s}_{:X}".format(candidatename, abs(suffix))
        newname = candidatename

        # Figure out whether we're adding a pythonic type or we were given a tinfo_t. If
        # we were given a tinfo_t, then use its size to allocate a place in the structure.
        res = interface.tinfo.parse(None, type, idaapi.PT_SIL) if isinstance(type, types.string) else type
        type, tinfo, tdescr = ([None, res.get_size()], res, "{!s}".format(res)) if isinstance(res, idaapi.tinfo_t) else (res, None, "{!s}".format(res))
        flag, typeid, nbytes = interface.typemap.resolve(type if tinfo is None or 0 < tinfo.get_size() < idaapi.BADSIZE else None)
        opinfo = idaapi.opinfo_t()
        opinfo.tid = typeid
        type_description = "{!r}".format("{!s}".format(res)) if isinstance(res, idaapi.tinfo_t) else "{!s}".format(type)

        # Now we have all the things that can prevent us from adding a member. We have
        # a fix for the name, but we need to verify that there's enough space available.
        if is_union and 0 <= realindex < sptr.memqty:
            mptr = sptr.members[realindex]
            fullname = member.fullname(mptr)
            raise E.InvalidParameterError(u"{:s}.add({:#x}, {:s}, {!s}, {:s}{:s}) : Unable to add a member to the requested {:s} due to the index ({:d}) already being used by \"{:s}\" ({:#x}).".format('.'.join([__name__, cls.__name__]), sptr.id, name_description, type_description, location_description, offset_description, 'union' if is_union else 'frame' if is_frame else 'structure', realindex, fullname, mptr.id))

        # If it's not a union, then we need to check if it will overlap another. If the
        # member is zero-length'd, then check the whole structure size because it can
        # only be a variable-length member which fills up the entirety of the structure.
        elif not is_union and any(cls.overlaps(sptr, realoffset, realoffset + (nbytes if nbytes else idaapi.get_struc_size(sptr)))):
            left, right = realoffset, realoffset + (nbytes if nbytes else idaapi.get_struc_size(sptr))
            iterable = cls.overlaps(sptr, left, right)
            problems = [mptr.id for mowner, mindex, mptr in iterable]
            raise E.InvalidTypeOrValueError(u"{:s}.add({:#x}, {:s}, {!s}, {:s}{:s}) : Unable to add a member to the requested {:s} due to its boundaries ({:s}) overlapping with {:d} member{:s} ({:s}).".format('.'.join([__name__, cls.__name__]), sptr.id, name_description, type_description, location_description, offset_description, 'union' if is_union else 'frame' if is_frame else 'structure', interface.bounds_t(base + left, base + right), len(problems), '' if len(problems) == 1 else 's', ', '.join(map("{:#x}".format, problems))))

        # If we're adding a variable-length member to the end of a variable-length
        # structure, then we can't add anything past the last member without overlap.
        elif is_variable and not nbytes and realoffset >= idaapi.get_struc_size(sptr):
            left, right = realoffset, realoffset + idaapi.get_struc_size(sptr) + 1
            iterable = cls.overlaps(sptr, left, right)
            problems = [mptr.id for mowner, mindex, mptr in iterable]
            raise E.InvalidTypeOrValueError(u"{:s}.add({:#x}, {:s}, {!s}, {:s}{:s}) : Unable to add a member to the requested {:s} due to its boundaries ({:s}) overlapping with {:d} member{:s} ({:s}).".format('.'.join([__name__, cls.__name__]), sptr.id, name_description, type_description, location_description, offset_description, 'union' if is_union else 'frame' if is_frame else 'structure', interface.bounds_t(base + left, base + right), len(problems), '' if len(problems) == 1 else 's', ', '.join(map("{:#x}".format, problems))))

        # Our very last check ensures that we don't pass a negative value as a location
        # to the disassembler. Although the disassembler recognizes BADADDR, we don't
        # because we wouldn't be able to find the member after it's been added.
        elif (realindex < 0 if is_union else realoffset < 0):
            description = "the index ({:d}) being invalid".format(realindex) if is_union else "the offset ({:#x}) being outside the boundaries ({:s}) of the {:s}".format(useroffset, interface.bounds_t(base, base + idaapi.get_struc_size(sptr)), 'union' if is_union else 'frame' if is_frame else 'structure')
            raise E.InvalidParameterError(u"{:s}.add({:#x}, {:s}, {!s}, {:s}{:s}) : Unable to add the member to the requested {:s} ({:#x}) due to {:s}.".format('.'.join([__name__, cls.__name__]), sptr.id, name_description, type_description, location_description, offset_description, 'union' if is_union else 'frame' if is_frame else 'structure', sptr.id, description))

        # If we had to adjust the name of the new member, then we just need
        # to issue a warning so that the user knows the name was changed.
        elif oldname != newname:
            mptr = idaapi.get_member_by_name(sptr, utils.string.to(oldname))
            logging.warning(u"{:s}.add({:#x}, {:s}, {!s}, {:s}{:s}) : Using alternative name \"{:s}\" for new member at offset {:+#x} due to a member ({:#x}) at offset {:+#x} using the requested name \"{:s}\".".format('.'.join([__name__, cls.__name__]), sptr.id, name_description, type_description, location_description, offset_description, utils.string.escape(newname, '"'), base + realoffset, mptr.id, mptr.soff + base, utils.string.escape(oldname, '"')))

        # Now that we've checked everything and complained about what we had to
        # fix, we can finally use the disassembler api to create the member.
        res = idaapi.add_struc_member(sptr, utils.string.to(newname), idaapi.BADADDR if is_union else realoffset, flag, opinfo, nbytes)
        if res != idaapi.STRUC_ERROR_MEMBER_OK:
            DisassemblerExceptionType = E.DuplicateItemError if res == idaapi.STRUC_ERROR_MEMBER_NAME else E.DisassemblerError
            error_name, error_description = cls.format_error_add_member(res)
            raise DisassemblerExceptionType(u"{:s}.add({:#x}, {:s}, {!s}, {:s}{:s}) : Unable to add a member to the requested {:s} due to error {:s}{:s}.".format('.'.join([__name__, cls.__name__]), sptr.id, name_description, type_description, location_description, offset_description, 'union' if is_union else 'frame' if is_frame else 'structure', error_name or "code {:d}".format(res), " ({:s})".format(error_description) if error_description else ''))

        # That should have done it, so we now need to return the newly created
        # member back to the caller. We accomplish this by trying to fetch the
        # member at the offset or index that it was supposed to be created at.
        mptr = idaapi.get_member(sptr, realindex if is_union else realoffset)
        if mptr is None:
            where = "index {:d}".format(realindex) if is_union else "offset {:#x}{:s}".format(realoffset, "{:+#x}".format(nbytes) if nbytes else '')
            raise E.MemberNotFoundError(u"{:s}.add({:#x}, {:s}, {!s}, {:s}{:s}) : Unable to find the recently created member \"{:s}\" at {:s} of the specified {:s} ({:#x}).".format('.'.join([__name__, cls.__name__]), sptr.id, name_description, type_description, location_description, offset_description, utils.string.escape(newname, '"'), where, 'union' if is_union else 'frame' if is_frame else 'structure', sptr.id))

        # If we were given a tinfo_t for the type, then we need to apply it to
        # the newly-created member. Our size should already be correct, so we
        # can just apply the typeinfo in a non-destructive (compatible) manner.
        res = idaapi.SMT_OK if tinfo is None else set_member_tinfo(sptr, mptr, mptr.soff, tinfo, idaapi.SET_MEMTI_COMPATIBLE)

        # If we couldn't apply the tinfo_t, then we need to complain. We can't
        # really remove the field we just created, because that would betray the
        # caller's request. So instead we log a critical error, since at least
        # the size of the member should be set to exactly what the user wanted.
        if res == idaapi.SMT_FAILED:
            where = "index {:d}".format(realindex) if is_union else "offset {:#x}{:s}".format(realoffset, "{:+#x}".format(nbytes) if nbytes else '')
            logging.fatal(u"{:s}.add({:#x}, {:s}, {!s}, {:s}{:s}) : Unable to apply the specified type to the new member \"{:s}\" at {:s} of the specified {:s} ({:#x}).".format('.'.join([__name__, cls.__name__]), sptr.id, name_description, type_description, location_description, offset_description, utils.string.escape(newname, '"'), where, 'union' if is_union else 'frame' if is_frame else 'structure', sptr.id))

        elif res not in {idaapi.SMT_OK, idaapi.SMT_KEEP}:
            error_name, error_description = cls.format_error_typeinfo(res)
            logging.fatal(u"{:s}.add({:#x}, {:s}, {!s}, {:s}{:s}) : Unable to apply the specified type to the new member \"{:s}\" at {:s} of the specified {:s} ({:#x}) due to error {:s}{:s}.".format('.'.join([__name__, cls.__name__]), sptr.id, name_description, type_description, location_description, offset_description, utils.string.escape("{!s}".format(tinfo), '"'), utils.string.escape(newname, '"'), where, 'union' if is_union else 'frame' if is_frame else 'structure', sptr.id, error_name or "code {:d}".format(res), " ({:s})".format(error_description) if error_description else ''))

        # Our work is done, we can log our small success and update the
        # refinfo_t of the member in case it is actually necessary.
        refcount = interface.address.update_refinfo(mptr.id, flag)
        fullname, where = member.fullname(mptr), "index {:d}".format(realindex) if is_union else "offset {:#x}{:s}".format(base + realoffset, "{:+#x}".format(nbytes) if nbytes else '')
        logging.debug(u"{:s}.add({:#x}, {:s}, {!s}, {:s}{:s}) : Succesfully added member \"{:s}\" at {:s} of the specified {:s} ({:#x}){:s}.".format('.'.join([__name__, cls.__name__]), sptr.id, name_description, type_description, location_description, offset_description, utils.string.escape(fullname, '"'), where, 'union' if is_union else 'frame' if is_frame else 'structure', sptr.id, " ({:d} references)".format(refcount) if refcount > 0 else ''))

        # If we successfully grabbed the member, then we need to figure out its
        # actual index in the structure. Then we can return it all to the caller.
        mindex = cls.index(sptr, mptr)
        return sptr, mindex, mptr

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
        '''Return the operand references from the database that reference this structure or its members.'''
        return members.references(self.ptr)

    def up(self):
        '''Return the structure members or references in the database that use this structure.'''
        result, sptr = [], self.ptr
        result.extend(xref.structure(sptr))
        return result

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
    def alignment(self):
        '''Return the alignment of the structure.'''
        sptr, shift = self.ptr, pow(2, 7)
        res, _ = divmod(sptr.props & idaapi.SF_ALIGN, shift)
        return pow(2, res)

    @alignment.setter
    def alignment(self, size):
        '''Modify the alignment of the structure to the specifyed `size`.'''
        sptr, shift = self.ptr, pow(2, 7)
        alignment, name = int(size), utils.string.of(idaapi.get_struc_name(sptr.id))
        res, _ = divmod(sptr.props & idaapi.SF_ALIGN, shift)
        e = math.floor(math.log(alignment, 2)) if alignment else 0
        if pow(2, math.trunc(e)) != alignment:
            cls = self.__class__
            raise E.InvalidParameterError(u"{:s}({:#x}).alignment({!s}) : Unable to change the alignment ({:+d}) for structure \"{:s}\" to an amount ({:d}) that is not a power of 2.".format('.'.join([__name__, cls.__name__]), sptr.id, size, pow(2, res), utils.string.escape(name, '"'), alignment))
        elif not (0 <= math.trunc(e) < 32):
            cls = self.__class__
            raise E.InvalidTypeOrValueError(u"{:s}({:#x}).alignment({!s}) : The requested alignment ({:+d}) for structure \"{:s}\" cannot be {:s} than {:s}.".format('.'.join([__name__, cls.__name__]), sptr.id, size, pow(2, math.trunc(e)), utils.string.escape(name, '"'), 'smaller' if math.trunc(e) < 32 else 'larger', "{:d}".format(pow(2, 0 if math.trunc(e) < 32 else 31))))
        elif not idaapi.set_struc_align(sptr, math.trunc(e)):
            cls = self.__class__
            raise E.DisassemblerError(u"{:s}({:#x}).alignment({!s}) : Unable to set the alignment for structure \"{:s}\" to the specified power of 2 ({:d}).".format('.'.join([__name__, cls.__name__]), sptr.id, size, utils.string.escape(name, '"'), math.trunc(e)))
        return pow(2, res)

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
        '''Return the operand references from the database that reference this member.'''
        return member.references(self.ptr)

    ### Properties
    @property
    def ptr(self):
        '''Return the pointer of the ``idaapi.member_t``.'''
        parent = self.__parent__
        mowner, mindex, mptr = members.by_index(parent.ptr, self.__index__)
        return mptr
    @property
    def id(self):
        '''Return the identifier of the member.'''
        mptr = self.ptr
        return mptr.id
    @property
    def properties(self):
        '''Return the properties for the current member.'''
        mptr = self.ptr
        return mptr.props
    @property
    def size(self):
        '''Return the size of the member.'''
        return member.size(self.ptr)
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
        '''Return the name of the member as a string.'''
        return member.get_name(self.ptr)
    @name.setter
    @utils.string.decorate_arguments('string')
    def name(self, string):
        '''Set the name of the member to the specified `string`.'''
        string = interface.tuplename(*string) if isinstance(string, types.ordered) else string

        # Type safety is fucking valuable, and in python it's an after-thought.
        if isinstance(string, (types.none, types.string)):
            return member.set_name(self.ptr, string) if string else member.remove_name(self.ptr)

        cls = self.__class__
        raise E.InvalidParameterError(u"{:s}({:#x}).name({!r}) : Unable to assign an unsupported type ({!s}) as the name for the member.".format('.'.join([__name__, cls.__name__]), self.id, string, string.__class__))

    @property
    def comment(self, repeatable=True):
        '''Return the repeatable comment of the member as a string.'''
        return member.get_comment(self.ptr, repeatable)
    @comment.setter
    @utils.string.decorate_arguments('string')
    def comment(self, string, repeatable=True):
        '''Set the repeatable comment of the member to the specified `string`.'''
        return member.set_comment(self.ptr, string, repeatable)

    @property
    def type(self):
        '''Return the type of the member in its pythonic form.'''
        return member.get_type(self.ptr, self.offset)
    @type.setter
    def type(self, type):
        """Set the type of the member to the given `type` non-destructively.

        If the given `type` is pythonic, then assign it in a non-destructive manner.
        If the given `type` is an ``idaapi.tinfo_t``, then apply it to the member destructively.
        """
        if not isinstance(type, (types.string, idaapi.tinfo_t)):
            return member.set_type(self.ptr, type)

        # if we were given a tinfo_t or a string to use, then we just use the typeinfo
        # api, but ensure that we use the flags that allow it to destroy other members.
        info = type if isinstance(type, idaapi.tinfo_t) else interface.tinfo.parse(None, type, idaapi.PT_SIL)
        if info is None:
            cls = self.__class__
            raise E.InvalidTypeOrValueError(u"{:s}({:#x}).type({!s}) : Unable to parse the specified type declaration ({!s}) for member {:s}.".format('.'.join([__name__, cls.__name__]), self.id, utils.string.repr("{!s}".format(type)), utils.string.repr(self.type), utils.string.escape("{!s}".format(self.name), '"')))
        return member.set_typeinfo(self.ptr, info, idaapi.SET_MEMTI_MAY_DESTROY)

    @property
    def typeinfo(self):
        '''Return the type information that has been applied to the member.'''
        return member.get_typeinfo(self.ptr)

    @typeinfo.setter
    def typeinfo(self, info):
        '''Set the type information of the member to `info` non-destructively.'''
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
            comments = tuple(member.get_comment(mptr, item) for item in [True, False])
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

        # We need to distinguish whether we can deserialize the type correctly, so
        # we grab its typeinfo and check the api for replace_ordinal_typerefs...
        tid = self.typeid
        tid = None if tid is None else new(tid, self.offset) if has(tid) else tid
        flag, size = mptr.flag, idaapi.get_member_size(mptr)
        ty = mptr.flag, tid, size

        # if the user applied some type information to the member, then we make sure
        # to serialize it (print_tinfo) so we can parse it back into the member.
        ti = member.get_typeinfo(mptr)
        if '__typeinfo__' in self.tag():
            res = idaapi.PRTYPE_1LINE | idaapi.PRTYPE_SEMI | idaapi.PRTYPE_NOARRS | idaapi.PRTYPE_RESTORE
            tname = idaapi.print_tinfo('', 0, 0, res, ti, '', '')
            tinfo = idaapi.print_tinfo('', 0, 0, res | idaapi.PRTYPE_DEF, ti, tname, '')

            # If we can concretize the type due to replace_ordinal_typerefs, then we
            # can include it as part of our list. Older versions will try to re-parse
            # the name, whereas newer versions can trust the deserialized type.
            serialized = [ti.serialize()] if hasattr(idaapi, 'replace_ordinal_typerefs') else []
            typeinfo = ty, [tname, tinfo] + serialized

        # If all the required methods are available, then we can serialize the type
        # without needing any sort of trickery. This requires replace_ordinal_typerefs.
        elif hasattr(idaapi, 'replace_ordinal_typerefs') and all(hasattr(ti, methodname) for methodname in ['serialize', 'get_type_name', 'get_final_type_name']):
            typeinfo = ty, [ti.get_final_type_name() or ti.get_type_name(), "{!s}".format(ti), ti.serialize()]

        # otherwise, we serialize the type into the older version. this shouldn't
        # get applied because there's a chance the type doesn't exist.
        else:
            typeinfo = ty, ti.serialize()

        # grab its comments
        cmtt = member.get_comment(mptr, True)
        cmtf = member.get_comment(mptr, False)
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
                member.set_name(mptr, newname)

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
                member.set_name(mptr, res)

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
        member.set_comment(mptr, cmtt, True)
        member.set_comment(mptr, cmtf, False)

        # if we're using the newest old tinfo version (a list), then try our
        # hardest to parse it. if we succeed, then we likely can apply it later.
        type_is_trusted = False
        if isinstance(ti, types.list) and len(ti) in {2, 3}:
            tname, tinfo, serialized = ti if len(ti) == 3 else itertools.chain(ti, [()])

            # First, we try to deserialize the type we were given. If it doesn't
            # exist or it fails, then we fall through to the next conditional.
            typeinfo, candidate = None, idaapi.tinfo_t()
            if serialized and len(serialized) in {1, 2, 3}:
                type_is_trusted, typeinfo = (True, candidate) if candidate.deserialize(interface.tinfo.library(), *serialized) else (type_is_trusted, None)

            # If we don't have any serialized data, then fall back to the old
            # variation where we try to parse the name into a primitive type.
            if not typeinfo:
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
        original = member.get_typeinfo(mptr) if mem in {idaapi.STRUC_ERROR_MEMBER_OK, idaapi.STRUC_ERROR_MEMBER_NAME, idaapi.STRUC_ERROR_MEMBER_OFFSET} else None
        original_typeinfo = "{!s}".format(original if original else idaapi.tinfo_t())
        typeinfo = typeinfo if any([not original, original and not original.present(), original.compare_with(typeinfo, idaapi.TCMP_EQUAL)]) else None

        # If we can trust that the type information was deserialized correctly,
        # with all of its ordinals being referenced by name, then we can just apply
        # it. Otherwise, we are only able to apply it if it doesn't use any ordinals.
        if typeinfo and (type_is_trusted or not any([typeinfo.get_ordinal(), typeinfo.is_array() and typeinfo.get_array_element().get_ordinal()])):

            # FIXME: if the type is a structure (udt), and none of its members were serialized,
            #        then things like field alignment and such are not applied. This results
            #        in a struct->til conversion failed error when trying to calc alignments.
            try:
                original = member.set_typeinfo(mptr, typeinfo)

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
            ti, ok = member.get_typeinfo(mptr), False
            try:
                original = member.set_typeinfo(mptr, ti)
                ok = True

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
        `referenced` - Filter the structure members that are referenced by code in the database
        `arguments` or `args` - Filter the frame members for any that are located within the arguments
        `locals` or `variables` - Filter the frame members for any that are local variables
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
        string = name if isinstance(name, types.ordered) else (name,)
        return members.has_name(self.owner.ptr, tuple(itertools.chain(string, suffix)))
    @utils.multicase(location=interface.location_t)
    def has(self, location):
        '''Return whether a member exists inside the specified `location`.'''
        get_data_elsize = idaapi.get_full_data_elsize if hasattr(idaapi, 'get_full_data_elsize') else idaapi.get_data_elsize

        # First unpack the location to convert both its components to integers, and
        # then translate them to the structure as if it was based at offset 0.
        offset, size = location
        if isinstance(offset, interface.symbol_t):
            [offset] = (int(item) for item in offset.symbols)
        sptr, realoffset, realsize = self.owner.ptr, offset - self.baseoffset, size

        # Now we can use it to get the list of candidates, then we can filter
        # out the ones that don't align with the realoffset we were given.
        candidates = (mptr for sptr, _, mptr in members.at_offset(sptr, realoffset))
        iterable = ((mptr, member.at(mptr, realoffset)) for mptr in candidates if member.contains(mptr, realoffset))
        filtered = [mptr for mptr, (index, moffset) in iterable if not moffset]

        # Finally, we check each member in our list of candidates against the size.
        for mptr in filtered:
            opinfo = idaapi.opinfo_t()
            retrieved = idaapi.retrieve_member_info(mptr, opinfo) if idaapi.__version__ < 7.0 else idaapi.retrieve_member_info(opinfo, mptr)
            melement, msize = get_data_elsize(mptr.id, mptr.flag, opinfo if retrieved else None), idaapi.get_member_size(mptr)

            # Here, we verify that the parameter size is a multiple of the member's
            # size, and that the size does not go outside the member's boundaries.
            # This confirms that the location selects at least one of its elements.
            index, remainder = divmod(realsize, melement)
            is_multiple = False if remainder else True

            left, right = realoffset, realoffset + melement * index
            is_variable = sptr.props & idaapi.SF_VAR and mptr.soff == mptr.eoff

            # If the size is a multiple of the element size, and the end of the
            # location is within the boundaries of the member, then we got a match.
            if is_multiple and realsize > 0 and any([is_variable, right <= mptr.soff + msize]):
                return True
            continue
        return False
    @utils.multicase(offset=types.integer)
    def has(self, offset):
        '''Return whether a member exists at the specified `offset`.'''
        owner, realoffset = self.owner, offset - self.baseoffset
        return members.has_offset(owner.ptr, realoffset)
    @utils.multicase(start=types.integer, end=types.integer)
    def has(self, start, end):
        '''Return whether any members exist from the offset `start` to the offset `end`.'''
        owner = self.owner
        start, stop = (offset - self.baseoffset for offset in sorted([start, end]))
        return members.has_bounds(owner.ptr, start, stop)
    @utils.multicase(bounds=interface.bounds_t)
    def has(self, bounds):
        '''Return whether any members exist within the specified `bounds`.'''
        start, stop = (offset - self.baseoffset for offset in sorted(bounds))
        return members.has_bounds(start, stop)
    @utils.multicase(structure=(idaapi.struc_t, structure_t))
    def has(self, structure):
        '''Return whether any members uses the specified `structure` as a field or references it as a pointer.'''
        FF_STRUCT = idaapi.FF_STRUCT if hasattr(idaapi, 'FF_STRUCT') else idaapi.FF_STRU

        # First, we get all the information for the structure parameter. We extract its id,
        # and then try to extract its type. We assume that its type is _always_ a structure.
        candidate = structure if isinstance(structure, idaapi.struc_t) else structure.ptr
        tid, tinfo = None if candidate.id == idaapi.BADADDR else candidate.id, address.type(candidate.id)
        stype = None if tinfo is None else interface.tinfo.structure(tinfo)

        # Iterate through all of the members and check first if the type
        # identifier matches the structure that we were given as a parameter.
        for sptr, midx, mptr in members.iterate(self.owner.ptr):
            opinfo = idaapi.opinfo_t()
            res = idaapi.retrieve_member_info(mptr, opinfo) if idaapi.__version__ < 7.0 else idaapi.retrieve_member_info(opinfo, mptr)
            if mptr.flag & idaapi.DT_TYPE == FF_STRUCT and res and res.tid == tid:
                return True

            # Otherwise we need to check if we're able to compare the type information that
            # was applied to the member, so we try to extract it and skip if we couldn't.
            mtype = address.type(mptr.id)
            if any([mtype is None, stype is None]):
                continue

            # Try to resolve the member's type to the structure it's based on. We use the
            # exception to assign "None" as the candidate if we couldn't resolve it.
            try: candidate = interface.tinfo.structure(mtype)
            except (E.DisassemblerError, TypeError): candidate = None

            # If there was a candidate and it actually matches, then we can return success.
            if candidate and interface.tinfo.equals(stype, candidate):
                return True
            continue
        return False
    @utils.multicase(info=idaapi.tinfo_t)
    def has(self, info):
        '''Return whether the types of any of the members are the same as the type information in `info`.'''
        owner = self.owner
        for sptr, midx, mptr in members.iterate(owner.ptr):
            mtype = address.type(mptr.id)
            if mtype is not None and interface.tinfo.equals(mtype, info):
                return True
            continue
        return False

    @utils.string.decorate_arguments('name', 'suffix')
    def by_name(self, name, *suffix):
        '''Return the member with the specified `name`.'''
        string = name if isinstance(name, types.ordered) else (name,)
        owner, res = self.owner, utils.string.to(interface.tuplename(*itertools.chain(string, suffix)))
        sptr, mindex, mptr = members.by_name(owner.ptr, res)
        return member_t(owner, mindex)
    byname = utils.alias(by_name, 'members_t')

    def by_offset(self, offset):
        '''Return the member at the specified `offset` from the base offset of the structure.'''
        cls, owner, realoffset = self.__class__, self.owner, int(offset) - self.baseoffset
        candidates = [item for item in members.in_offset(owner.ptr, realoffset)]

        # If we only found one candidate, then that was it and we can return it.
        if len(candidates) == 1:
            [(sptr, mindex, sptr)] = candidates
            return member_t(owner, mindex)

        # If it's a union, then there can be multiple members for a given offset. In
        # this situation we could log a warning, but we instead return the first one.
        elif union(owner.ptr) and candidates:
            [(sptr, mindex, sptr)] = candidates[:1]
            return member_t(owner, mindex)

        # There's no reason that there should be more than one member, so abort if there is.
        # However, if there are no members then we can just raise an exception and be done.
        left, size = self.baseoffset, idaapi.get_struc_size(owner.ptr)
        description = "{:#x}".format(offset) if isinstance(offset, types.integer) else "{!s}".format(offset)

        if not members.contains(owner.ptr, offset):
            raise E.MemberNotFoundError(u"{:s}({:#x}).members.by_offset({:s}) : Unable to locate a member at the specified offset ({:+#x}) of the {:s}.".format('.'.join([__name__, cls.__name__]), owner.ptr.id, description, int(offset), 'union' if union(owner.ptr) else 'frame' if frame(owner.ptr) else 'structure'))
        elif not size:
            raise E.OutOfBoundsError(u"{:s}({:#x}).members.by_offset({:s}) : Requested offset ({:+#x}) cannot exist within the {:s} due to its size ({:d}).".format('.'.join([__name__, cls.__name__]), owner.ptr.id, description, int(offset), 'union' if union(owner.ptr) else 'frame' if frame(owner.ptr) else 'structure', size))
        raise E.OutOfBoundsError(u"{:s}({:#x}).members.by_offset({:s}) : Requested offset ({:+#x}) is outside of the {:s} ({:#x}..{:#x}).".format('.'.join([__name__, cls.__name__]), owner.ptr.id, description, int(offset), 'union' if union(owner.ptr) else 'frame' if frame(owner.ptr) else 'structure', left, left + size - 1))
    byoffset = utils.alias(by_offset, 'members_t')

    def by_realoffset(self, offset):
        '''Return the member at the specified `offset` of the structure.'''
        cls, owner, realoffset = self.__class__, self.owner, int(offset)
        candidates = [item for item in members.in_offset(owner.ptr, realoffset)]

        # If there was only one result, then there's nothing else to do but return it.
        if len(candidates) == 1:
            [(sptr, mindex, sptr)] = candidates
            return member_t(owner, mindex)

        # If our structure is a union, then getting more than one member was expected.
        # So, we will simply trust the order that was determined by `members.in_offset`.
        elif union(owner.ptr) and candidates:
            [(sptr, mindex, sptr)] = candidates[:1]
            return member_t(owner, mindex)

        # Now we'll check our current state and figure out which exception needs raising.
        left, size = self.baseoffset, idaapi.get_struc_size(owner.ptr)
        description = "{:#x}".format(offset) if isinstance(offset, types.integer) else "{!s}".format(offset)

        if members.contains(owner.ptr, offset):
            raise E.MemberNotFoundError(u"{:s}({:#x}).members.by_realoffset({:s}) : Unable to locate a member at the specified offset ({:+#x}) of the {:s}.".format('.'.join([__name__, cls.__name__]), owner.ptr.id, description, int(offset), 'union' if union(owner.ptr) else 'frame' if frame(owner.ptr) else 'structure'))
        elif not size:
            raise E.OutOfBoundsError(u"{:s}({:#x}).members.by_realoffset({:s}) : Requested offset ({:+#x}) cannot exist within the {:s} due to its size ({:d}).".format('.'.join([__name__, cls.__name__]), owner.ptr.id, description, int(offset), 'union' if union(owner.ptr) else 'frame' if frame(owner.ptr) else 'structure', size))
        raise E.OutOfBoundsError(u"{:s}({:#x}).members.by_realoffset({:s}) : Requested offset ({:+#x}) is outside of the {:s} ({:#x}..{:#x}).".format('.'.join([__name__, cls.__name__]), owner.ptr.id, description, int(offset), 'union' if union(owner.ptr) else 'frame' if frame(owner.ptr) else 'structure', left, left + size - 1))
    byrealoffset = utils.alias(by_realoffset, 'members_t')

    def by_identifier(self, id):
        '''Return the member in the structure that has the specified `id`.'''
        owner = self.owner
        sptr, mindex, mptr = members.by_identifier(owner.ptr, id)
        return member_t(owner, mindex)
    by_id = byid = byidentifier = utils.alias(by_identifier, 'members_t')

    ## Adding and removing members from a structure.
    def index(self, member):
        '''Return the index of the specified `member` within the structure.'''
        cls, owner = self.__class__, self.owner
        if not hasattr(member, 'id'):
            raise E.InvalidParameterError(u"{:s}({:#x}).members.index({!r}) : An invalid type ({!s}) was specified as the member being requested.".format('.'.join([__name__, cls.__name__]), owner.ptr.id, member, member.__class__))
        identifier = member.id

        # Iterate through all of the members and find the index that matches.
        try:
            sptr, mindex, mptr = members.by_identifier(owner.ptr, identifier)
        except E.MemberNotFoundError:
            Fget_full_name = utils.fcompose(getattr(idaapi, 'ea2node', utils.fidentity), internal.netnode.name.get, utils.string.of)
            raise E.MemberNotFoundError(u"{:s}({:#x}).members.index({!s}) : The requested member ({!s}) does not belong to the current {:s} ({:#x}).".format('.'.join([__name__, cls.__name__]), owner.ptr.id, "{:#x}".format(identifier) if isinstance(member, (member_t, idaapi.member_t)) else "{!r}".format(member), Fget_full_name(identifier), 'union' if union(owner.ptr) else 'frame' if frame(owner.ptr) else 'structure', owner.ptr.id))
        return mindex

    @utils.multicase(index=types.integer)
    def pop(self, index):
        '''Remove the member at the specified `index` of the structure.'''
        cls, owner, base = self.__class__, self.owner, self.baseoffset
        results = members.remove_slice(owner.ptr, index, base)
        if not results:
            raise E.DisassemblerError(u"{:s}({:#x}).members.pop({:d}) : Unable to remove the member at index {:d} of the {:s} ({:#x}).".format('.'.join([__name__, cls.__name__]), owner.ptr.id, index, index, 'union' if union(owner.ptr) else 'frame' if frame(owner.ptr) else 'structure', owner.ptr.id))
        [(mname, mtype, mlocation, mtypeinfo, mcomments)] = results
        return mname, mtype, mlocation, mtypeinfo

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
        owner, sptr, size = self.owner, self.owner.ptr, idaapi.get_struc_size(self.owner.ptr)

        # If this is a union, then there is no offset and we need to use the quantity.
        if union(sptr):
            mowner, mindex, mptr = members.add(sptr, name, type, sptr.memqty)

        # Anything else and we can just use a base offset of 0 with
        # the structure size as the location for the member to add.
        else:
            mowner, mindex, mptr = members.add(sptr, name, type, size, 0)
        return member_t(owner, mindex)
    @utils.multicase(name=(types.string, types.ordered), offset=types.integer)
    @utils.string.decorate_arguments('name')
    def add(self, name, type, offset):
        '''Add a member at the specified `offset` of the structure with the given `name` and `type`.'''
        owner, sptr = self.owner, self.owner.ptr

        # If this case is being used with a union, then we need
        # to abort. No such thing as an offset within a union.
        if union(sptr):
            raise E.InvalidParameterError(u"{:s}({:#x}).members.add({!r}, {!s}, {:+#x}) : Refusing to add a member \"{:s}\" at a specific offset {:#x} of a {:s} ({:#x}).".format('.'.join([__name__, cls.__name__]), sptr.id, name, utils.string.repr(tdescr), utils.string.escape(name, '"'), offset, 'union' if union(sptr) else 'frame' if frame(sptr) else 'structure', sptr.id))

        # We explicitly trust whatever offset the user gives us.
        elif frame(sptr):
            mowner, mindex, mptr = members.add(sptr, name, type, offset, owner.baseoffset)
        else:
            mowner, mindex, mptr = members.add(sptr, name, type, offset, owner.baseoffset)
        return member_t(owner, mindex)

    @utils.multicase(offset=types.integer)
    def remove(self, offset):
        '''Remove the member at the specified `offset` of the structure.'''
        cls, owner, items = self.__class__, self.owner, [packed for packed in members.at_offset(offset - self.baseoffset)]

        # If there are no items or more than one at the requested offset than
        # we bail because of there being either no member or it's a union.
        if not items:
            raise E.MemberNotFoundError(u"{:s}({:#x}).members.remove({:+#x}) : Unable to find a member at the specified offset ({:#x}) of the {:s} ({:s}).".format('.'.join([__name__, cls.__name__]), owner.ptr.id, offset, offset, 'union' if union(owner.ptr) else 'frame' if frame(owner.ptr) else 'structure', owner.bounds))

        elif len(items) > 1:
            raise E.InvalidTypeOrValueError(u"{:s}({:#x}).members.remove({:+#x}) : Refusing to remove more than {:d} member{:s} ({:d}) at offset {:#x}.".format('.'.join([__name__, cls.__name__]), owner.ptr.id, offset, 1, '' if len(items) == 1 else 's', len(items), offset))

        # Grab the single item out of our list of results, and remove it.
        [(mowner, mindex, mptr)] = items
        results = members.remove_slice(owner.ptr, mindex, self.baseoffset)
        if not results:
            raise E.DisassemblerError(u"{:s}({:#x}).members.remove({:+#x}) : Unable to remove the member at index {:d} of the {:s} for the specified offset ({:#x}).".format('.'.join([__name__, cls.__name__]), owner.ptr.id, offset, mindex, 'union' if union(owner.ptr) else 'frame' if frame(owner.ptr) else 'structure', self.baseoffset + mptr.soff))

        # Return whatever it was that we just removed.
        [(mname, mtype, mlocation, mtypeinfo, mcomments)] = results
        return mname, mtype, mlocation, mtypeinfo
    @utils.multicase(bounds=interface.bounds_t)
    def remove(self, bounds):
        '''Remove the members from the structure within the specified `bounds`.'''
        owner, base = self.owner, self.baseoffset
        start, stop = bounds
        removed = members.remove_bounds(owner.ptr, start, stop, base)
        return [(mname, mtype, mlocation, mtypeinfo) for mid, mname, mtype, mlocation, mtypeinfo, mcomments in removed]
    @utils.multicase(start=types.integer, stop=types.integer)
    def remove(self, start, stop):
        '''Remove the members of the structure from the offset `start` to `stop`.'''
        owner, base = self.owner, self.baseoffset
        # FIXME: this should remove overlapping members
        removed = members.remove_bounds(owner.ptr, start, stop, base)
        return [(mname, mtype, mlocation, mtypeinfo) for mid, mname, mtype, mlocation, mtypeinfo, mcomments in removed]
    @utils.multicase(location=interface.location_t)
    def remove(self, location):
        '''Remove the members at the specified `location` of the structure.'''
        owner, base = self.owner, self.baseoffset
        start, stop = location.bounds
        removed = members.remove_bounds(owner.ptr, start, stop, base)
        return [(mname, mtype, mlocation, mtypeinfo) for mid, mname, mtype, mlocation, mtypeinfo, mcomments in removed]

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
    __members_matcher.mapping('arguments', operator.truth, 'ptr', utils.fcondition(utils.fcompose(operator.attrgetter('id'), idaapi.get_member_by_id, bool))(utils.fcompose(utils.fthrough(utils.fcompose(operator.attrgetter('id'), idaapi.get_member_by_id, operator.itemgetter(-1), operator.attrgetter('id'), idaapi.get_func_by_frame, utils.fcondition(utils.fcompose(idaapi.get_func, bool))(utils.fcompose(idaapi.get_func, idaapi.frame_off_args, functools.partial(functools.partial, operator.le)), functools.partial(functools.partial, utils.fconstant(False)))), operator.attrgetter('soff')), utils.funpack(utils.fapplyto())), utils.fconstant(False)))
    __members_matcher.alias('args', 'arguments'), __members_matcher.alias('parameters', 'arguments'),
    __members_matcher.mapping('locals', operator.truth, 'ptr', utils.fcondition(utils.fcompose(operator.attrgetter('id'), idaapi.get_member_by_id, bool))(utils.fcompose(utils.fthrough(utils.fcompose(operator.attrgetter('id'), idaapi.get_member_by_id, operator.itemgetter(-1), operator.attrgetter('id'), idaapi.get_func_by_frame, utils.fcondition(utils.fcompose(idaapi.get_func, bool))(utils.fcompose(idaapi.get_func, idaapi.frame_off_savregs, functools.partial(functools.partial, operator.gt)), functools.partial(functools.partial, utils.fconstant(False)))), operator.attrgetter('soff')), utils.funpack(utils.fapplyto())), utils.fconstant(False)))
    __members_matcher.alias('lvars', 'locals'), __members_matcher.alias('variables', 'locals'),
    __members_matcher.mapping('referenced', operator.truth, 'ptr', member.has_references, bool)
    __members_matcher.predicate('predicate'), __members_matcher.predicate('pred')

    def __iterate__(self):
        '''Yield each of the members within the structure.'''
        owner = self.owner
        for sptr, mindex, mptr in members.iterate(owner.ptr):
            yield member_t(owner, mindex)
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
        res, owner = [], self.owner
        base, mn, ms, mti, eoff = self.baseoffset, 0, 0, 0, self.baseoffset
        for sptr, mindex, mptr in members.iterate(owner.ptr):
            moffset, t = base if union(sptr) else base + mptr.soff, member.get_type(mptr, 0 if union(sptr) else base + mptr.soff)
            res.append((-1, '', [None, moffset - eoff], None, eoff, moffset - eoff, '', {})) if eoff < moffset else None
            name, ti, msize, comment, tag = (F(mptr) for F in [member.get_name, member.get_typeinfo, idaapi.get_member_size, member.get_comment, internal.tags.member.get])
            res.append((mindex, name, t, ti, moffset, msize, comment or '', tag))
            mn = max(mn, len(name))
            ms = max(ms, len("{:+#x}".format(moffset - base)))
            ms = max(ms, len("{:+#x}".format(msize)))
            mti = max(mti, len("{!s}".format(ti.dstr()).replace(' *', '*')))
            eoff = base + mptr.eoff

        mi = len("{:d}".format(len(self) - 1)) if len(self) else 1

        if len(self):
            mo = max(map(len, map("{:x}".format, [self.baseoffset, self[-1].offset + self[-1].size])))
            return "{!r}\n{:s}".format(self.owner, '\n'.join("{:<{:d}s} {:>{:d}x}{:<+#{:d}x} {:>{:d}s} {:<{:d}s} {!s}{:s}".format('' if i < 0 else "[{:d}]".format(i), 2 + mi, o, mo, s, ms, "{!s}".format(ti.dstr()).replace(' *','*') if ti else '', mti, '' if i < 0 else utils.string.repr(n), mn + 2, utils.string.repr(t), " // {!s}".format(utils.string.repr(T) if '\n' in c else utils.string.to(c)) if c else '') for i, n, t, ti, o, s, c, T in res))
        return "{!r}".format(self.owner)

    def __unicode__(self):
        '''Render all of the fields within the current structure.'''
        res, owner = [], self.owner
        base, mn, ms, mti, eoff = self.baseoffset, 0, 0, 0, self.baseoffset
        for sptr, mindex, mptr in members.iterate(owner.ptr):
            moffset, t = base if union(sptr) else base + mptr.soff, member.get_type(mptr, 0 if union(sptr) else base + mptr.soff)
            name, ti, msize, comment, tag = (F(mptr) for F in [member.get_name, member.get_typeinfo, idaapi.get_member_size, member.get_comment, internal.tags.member.get])
            res.append((-1, '', [None, moffset - eoff], None, eoff, moffset - eoff, '', {})) if eoff < moffset else None
            res.append((mindex, name, t, ti, moffset, msize, comment or '', tag))
            mn = max(mn, len(name))
            ms = max(ms, len("{:+#x}".format(moffset - base)))
            ms = max(ms, len("{:+#x}".format(msize)))
            mti = max(mti, len("{!s}".format(ti.dstr()).replace(' *', '*')))
            eoff = base + mptr.eoff

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
            sptr, mindex, mptr = members.by_index(owner.ptr, index)
            res = member_t(owner, mindex)

        elif isinstance(index, types.string):
            sptr, mindex, mptr = members.by_name(owner.ptr, index)
            res = member_t(owner, mindex)

        elif isinstance(index, slice):
            left, right, layout = members.layout_getslice(owner.ptr, index)
            iterable = (member_or_size for offset, member_or_size in layout)
            iterable_packed = ((members.by_identifier(owner.ptr, member_or_size) if isinstance(member_or_size, idaapi.member_t) else member_or_size) for member_or_size in iterable)
            res = [(owner_index_member if isinstance(owner_index_member, types.integer) else member_t(owner, owner_index_member[1])) for owner_index_member in iterable_packed]

        else:
            cls = self.__class__
            raise E.InvalidParameterError(u"{:s}({:#x}).members.__getitem__({!r}) : An invalid type ({!s}) was specified for the index.".format('.'.join([__name__, cls.__name__]), owner.ptr.id, index, index.__class__))

        if res is None:
            cls, where = self.__class__, "with the specified name (\"{:s}\")".format(index) if isinstance(index, types.string) else "at the given index ({:d})".format(index)
            raise E.MemberNotFoundError(u"{:s}({:#x}).members.__getitem__({:d}) : Unable to find a member {:s}.".format('.'.join([__name__, cls.__name__]), owner.ptr.id, index, where))
        return res

    def __setitem__(self, index, item):
        '''Replace the member(s) within the specified `index` with a copy of the specified `item` or list of items.'''
        sptr, base = self.owner.ptr, self.baseoffset
        removed = members.layout_setslice(sptr, index, item, base)
        return [(mname, mtype, mlocation, mtypeinfo) for mname, mtype, mlocation, mtypeinfo, mcomments in removed]

    def __delitem__(self, index):
        '''Remove the member(s) at the specified `index` non-destructively.'''
        sptr, base = self.owner.ptr, self.baseoffset
        removed = members.clear_slice(sptr, index, base)
        return [(mname, mtype, mlocation, mtypeinfo) for mname, mtype, mlocation, mtypeinfo, mcomments in removed]

    def __iter__(self):
        '''Yield all the members within the structure.'''
        owner = self.owner
        for sptr, mindex, mptr in members.iterate(owner.ptr):
            yield member_t(owner, mindex)
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
