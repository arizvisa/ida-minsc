"""
This module is used for reading and writing tags to an address, function,
structure, or structure member within the database. It primarily revolves
around the tools provided by the `internal.comment` module, and uses them
to maintain any of the indices or caches that are necessary for performance.
"""
import idaapi, internal, operator, logging
from internal import utils, interface, declaration, comment

class address(object):
    """
    This namespace is responsible for reading from and writing tags to
    an address. Each address can be either a global or associated with
    the contents of a function and supports the following implicit tags:

        `__name__` - The name for the address which is preserved if the name is mangled.
        `__color__` - The color of the item at the given address..
        `__extra_prefix__` - The anterior comment of the item at the given address.
        `__extra_suffix__` - The posterior comment of the item at the given address.
        `__typeinfo__` - Any type information that is associated with the address.

    The tags for each address are indexed and maintained using the
    namespaces that inherit from the `internal.comment.tagging` namespace.
    """

    @classmethod
    def get(cls, ea):
        '''Return a dictionary containing the tags for the item at the address `ea`.'''
        MANGLED_CODE, MANGLED_DATA, MANGLED_UNKNOWN = getattr(idaapi, 'MANGLED_CODE', 0), getattr(idaapi, 'MANGLED_DATA', 1), getattr(idaapi, 'MANGLED_UNKNOWN', 2)
        Fmangled_type = idaapi.get_mangled_name_type if hasattr(idaapi, 'get_mangled_name_type') else utils.fcompose(utils.frpartial(idaapi.demangle_name, 0), utils.fcondition(operator.truth)(0, MANGLED_UNKNOWN))
        MNG_NODEFINIT, MNG_NOPTRTYP = getattr(idaapi, 'MNG_NODEFINIT', 8), getattr(idaapi, 'MNG_NOPTRTYP', 7)

        ea = interface.address.inside(int(ea))

        # Check if we're within a function and determine whether it's a
        # runtime-linked address or not. If we're within a function, then
        # we need to ensure that we're using non-repeatable comments.
        try:
            func = interface.function.by_address(ea)
            rt, _ = interface.addressOfRuntimeOrStatic(ea if func is None else func)

        # If the address is not within a function, then assign some variables
        # so that we will use a repeatable comment.
        except LookupError:
            rt, func = False, None
        repeatable = False if func and interface.function.has(ea) and not rt else True

        # Read both repeatable and non-repeatable comments from the chosen
        # address so that we can decode both of them into dictionaries to
        # use. We also decode the (repeatable) function comment, because in
        # some cases a function is created for a runtime-linked address.
        d1 = comment.decode(utils.string.of(idaapi.get_cmt(ea, False) or ''))
        d2 = comment.decode(utils.string.of(idaapi.get_cmt(ea, True) or ''))
        d3 = comment.decode(utils.string.of(idaapi.get_func_cmt(func, True) or '') if rt else '')
        d1keys, d2keys, d3keys = ({key for key in item} for item in [d1, d2, d3])

        # Check if the address had content in either decoding types of
        # comments so that we can warn the user about it.
        if d1keys & d2keys:
            logging.info(u"{:s}.tag({:#x}) : Contents of both the repeatable and non-repeatable comment conflict with one another due to using the same keys ({:s}). Giving the {:s} comment priority.".format('database', ea, ', '.join(operator.and_(d1keys, d2keys)), 'repeatable' if repeatable else 'non-repeatable'))
        if rt and (operator.and_(d3keys, d1keys) or operator.and_(d3keys, d2keys)):
            logging.info(u"{:s}.tag({:#x}) : Contents of the runtime-linked comment conflict with one of the database comments due to using the same keys ({:s}). Giving the {:s} comment priority.".format('database', ea, ', '.join(operator.and_(d3keys, d2keys) or operator.and_(d3keys, d1keys)), 'function'))

        # Merge all of the decoded tags into a dictionary while giving priority
        # to the correct one. If the address was pointing to a runtime-linked
        # address and was a case that had a function comment, then we need to
        # give those tags absolute priority when building our dictionary.
        res = {}
        [res.update(d) for d in ([d1, d2] if repeatable else [d2, d1])]
        rt and res.update(d3)

        # First thing we need to figure out is whether the name exists and if
        # it's actually special in that we need to demangle it for the real name.
        aname = interface.name.get(ea)
        if aname and Fmangled_type(utils.string.to(aname)) != MANGLED_UNKNOWN:
            realname = utils.string.of(idaapi.demangle_name(utils.string.to(aname), MNG_NODEFINIT|MNG_NOPTRTYP) or aname)
        else:
            realname = aname or ''

        # Add any of the implicit tags for the specified address to our results.
        if aname and interface.address.flags(ea, idaapi.FF_NAME): res.setdefault('__name__', realname)
        if comment.extra.has_prefix(ea): res.setdefault('__extra_prefix__', comment.extra.get_prefix(ea))
        if comment.extra.has_suffix(ea): res.setdefault('__extra_suffix__', comment.extra.get_suffix(ea))

        # If there was some type information associated with the address, then
        # we need its name so that we can format it and add it as an implicit tag.
        try:
            if interface.address.has_typeinfo(ea):
                ti = interface.address.typeinfo(ea)

                # We need the name to be parseable and IDA just doesn't give a fuck if it outputs
                # something non-parseable. So we simply fix that here and render the typeinfo.
                validname = declaration.unmangled.parsable(realname)
                ti_s = idaapi.print_tinfo('', 0, 0, 0, ti, utils.string.to(validname), '')

                # Add it to our dictionary that we return to the user.
                res.setdefault('__typeinfo__', ti_s)

        # If we caught an exception, then the name from the type information could be
        # mangled and so we need to rip the type information directly out of the name.
        except internal.exceptions.InvalidTypeOrValueError:
            demangled = declaration.demangle(aname)

            # if the demangled name is different from the actual name, then we need
            # to extract its result type and prepend it to the demangled name.
            if demangled != aname:
                res.setdefault('__typeinfo__', demangled)

        # Add the implicit color to the result dictionary if one was actually set.
        col, DEFCOLOR = interface.address.color(ea), 0xffffffff
        if col != DEFCOLOR: res.setdefault('__color__', col)

        return res

class function(object):
    """
    This namespace is responsible for reading from and writing tags for
    a function. The tags belonging to a function are considered global
    tags that are distinctly separate from the function's contents. This
    type of tagging supports the following implicit tags:

        `__name__` - The name of the given function demangled if it is mangled.
        `__color__` - The color of the entire function.
        `__typeinfo__` - The type information of the function which contains its prototype.

    The tags for each individual function are indexed and maintained using
    the `internal.comment.global` namespace.
    """

    @classmethod
    def get(cls, func):
        '''Return a dictionary containing the tags for the function `func`.'''
        MANGLED_CODE, MANGLED_DATA, MANGLED_UNKNOWN = getattr(idaapi, 'MANGLED_CODE', 0), getattr(idaapi, 'MANGLED_DATA', 1), getattr(idaapi, 'MANGLED_UNKNOWN', 2)
        Fmangled_type = idaapi.get_mangled_name_type if hasattr(idaapi, 'get_mangled_name_type') else utils.fcompose(utils.frpartial(idaapi.demangle_name, 0), utils.fcondition(operator.truth)(0, MANGLED_UNKNOWN))
        MNG_NODEFINIT, MNG_NOPTRTYP, MNG_LONG_FORM = getattr(idaapi, 'MNG_NODEFINIT', 8), getattr(idaapi, 'MNG_NOPTRTYP', 7), getattr(idaapi, 'MNG_LONG_FORM', 0x6400007)

        try:
            rt, ea = interface.addressOfRuntimeOrStatic(func)

        # If the given location was not within a function, then fall back to a database tag.
        except internal.exceptions.FunctionNotFoundError:
            parameter = ("{:#x}" if isinstance(func, internal.types.integer) else "{!r}").format(func)
            logging.warning(u"{:s}.tag({:s}) : Attempted to read any tags from a non-function ({:s}). Falling back to using database tags.".format('function', parameter, parameter))
            return address.get(func)

        # If we were given a runtime function, then the address actually uses a database tag.
        if rt:
            logging.warning(u"{:s}.tag({:#x}) : Attempted to read any tags from a runtime-linked address ({:#x}). Falling back to using database tags.".format('function', ea, ea))
            return address.get(ea)

        # Read both repeatable and non-repeatable comments from the address, and
        # decode the tags that are stored within to a dictionary.
        fn, repeatable = interface.function.by_address(ea), True
        d1 = comment.decode(utils.string.of(idaapi.get_func_cmt(fn, False) or ''))
        d2 = comment.decode(utils.string.of(idaapi.get_func_cmt(fn, True) or ''))
        d1keys, d2keys = ({key for key in item} for item in [d1, d2])

        # Detect if the address had content in both repeatable or non-repeatable
        # comments so we can warn the user about what we're going to do.
        if d1keys & d2keys:
            logging.info(u"{:s}.tag({:#x}) : Contents of both the repeatable and non-repeatable comment conflict with one another due to using the same keys ({!r}). Giving the {:s} comment priority.".format('function', ea, ', '.join(d1keys & d2keys), 'repeatable' if repeatable else 'non-repeatable'))

        # Then we can store them into a dictionary whilst preserving priority.
        res = {}
        [ res.update(d) for d in ([d1, d2] if repeatable else [d2, d1]) ]

        # Collect all of the naming information for the function.
        fname, mangled = interface.function.name(ea), utils.string.of(idaapi.get_func_name(ea))
        if fname and Fmangled_type(utils.string.to(mangled)) != MANGLED_UNKNOWN:
            realname = utils.string.of(idaapi.demangle_name(utils.string.to(mangled), MNG_NODEFINIT|MNG_NOPTRTYP) or fname)
        else:
            realname = fname or ''

        # Add any of the implicit tags for the given function into our results.
        fname = fname
        if fname and interface.address.flags(interface.range.start(fn), idaapi.FF_NAME): res.setdefault('__name__', realname)

        # For the function's type information within the implicit "__typeinfo__"
        # tag, we'll need to extract the prototype and the function's name. This
        # is so that we can use the name to emit a proper function prototype.
        try:
            if interface.function.has_typeinfo(fn):
                ti = interface.function.typeinfo(fn)

                # We need this name to be parseable and (of course) IDA doesn't
                # give a fuck whether its output is parseable by its own parser.
                validname = declaration.unmangled.parsable(realname)
                fprototype = idaapi.print_tinfo('', 0, 0, 0, ti, utils.string.to(validname), '')
                res.setdefault('__typeinfo__', fprototype)

        # If an exception was raised, then we're using an older version of IDA and we
        # need to rip the type information from the unmangled name.
        except internal.exceptions.InvalidTypeOrValueError:
            None if fname == realname else res.setdefault('__typeinfo__', fname)

        # Add the color to the result if one was actually set.
        fcolor, DEFCOLOR = interface.function.color(fn), 0xffffffff
        if fcolor != DEFCOLOR: res.setdefault('__color__', fcolor)

        return res

class structure(object):
    """
    This namespace is responsible for the tags belonging to a structure,
    and provides functions for reading and writing to them. These tags
    are not generally queried, but are instead used for filtering a list
    of structures. The implicit tags that are available for a structure
    are instead used to expose certain characteristics about the definition
    of a structure. The implicit tags that are available are:

        `__name__` - The name of the structure, but only if it is listed by the structure list.
        `__typeinfo__` - The type for the structure, but only if the structure was explicitly created or modified by the user.

    The tags belonging to each structure are not indexed by the plugin.
    """

    @classmethod
    def get(cls, sptr):
        '''Return a dictionary containing the tags for the structure given by `sptr`.'''
        repeatable, sptr = True, idaapi.get_struc(int(sptr)) if isinstance(sptr, internal.types.integer) else sptr

        # grab the repeatable and non-repeatable comment for the structure
        d1 = comment.decode(utils.string.of(idaapi.get_struc_cmt(sptr.id, False)))
        d2 = comment.decode(utils.string.of(idaapi.get_struc_cmt(sptr.id, True)))
        d1keys, d2keys = ({key for key in item} for item in [d1, d2])

        # check for duplicate keys
        if d1keys & d2keys:
            logging.info(u"{:s}({:#x}).tag() : The repeatable and non-repeatable comment for structure {:s} use the same tags ({!r}). Giving priority to the {:s} comment.".format(cls.__name__, sptr.id, utils.string.repr(utils.string.of(idaapi.get_struc_name(sptr.id))), ', '.join(d1keys & d2keys), 'repeatable' if repeatable else 'non-repeatable'))

        # merge the dictionaries into one and return it (XXX: return a dictionary that automatically updates the comment when it's updated)
        res = {}
        [res.update(d) for d in ([d1, d2] if repeatable else [d2, d1])]

        # Now we need to add implicit tags which are related to the structure.

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
            ti = interface.address.typeinfo(sptr.id)
            ti_s = idaapi.print_tinfo('', 0, 0, 0, ti, '', '')
            res.setdefault('__typeinfo__', ti_s)
        return res

class member(object):
    """
    This namespace is responsible for the tags belonging to a member
    within a structure.  Similar to a structure, the structure member
    provides implicit tags that are used to expose specific characteristics
    of the member to the user. These implicit tags are as follows:

        `__name__` - The name of the member, but only if the name is not the default.
        `__typeinfo__` - The type information for the member if it exists.

    The tags belonging to each structure member are not indexed by the plugin.
    """

    @classmethod
    def get(cls, mptr):
        '''Return a dictionary containing the tags for the structure member given by `mptr`.'''
        repeatable, mptr = True, idaapi.get_struc(int(mptr)) if isinstance(mptr, internal.types.integer) else mptr
        mptr, fullname, sptr = idaapi.get_member_by_id(mptr.id)

        # grab the repeatable and non-repeatable comment
        d1 = comment.decode(utils.string.of(idaapi.get_member_cmt(mptr.id, False)))
        d2 = comment.decode(utils.string.of(idaapi.get_member_cmt(mptr.id, True)))
        d1keys, d2keys = ({key for key in item} for item in [d1, d2])

        # check for duplicate keys
        if d1keys & d2keys:
            logging.info(u"{:s}({:#x}).tag() : The repeatable and non-repeatable comment for {:s} use the same tags ({!r}). Giving priority to the {:s} comment.".format(cls.__name__, mptr.id, utils.string.repr(utils.string.of(idaapi.get_member_fullname(mptr.id))), ', '.join(d1keys & d2keys), 'repeatable' if repeatable else 'non-repeatable'))

        # merge the dictionaries into one before adding implicit tags.
        res = {}
        [res.update(d) for d in ([d1, d2] if repeatable else [d2, d1])]

        # the format of the implicit tags depend on the type of the member, which
        # we actually extract from a combination of the name, and is_special_member.
        specialQ = True if idaapi.is_special_member(mptr.id) else False

        # now we need to check the name via is_dummy_member_name, and explicitly
        # check to see if the name begins with field_ so that we don't use it if so.
        idaname = idaapi.get_member_name(mptr.id) or ''
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
        user_tinfoQ = idaapi.get_aflags(mptr.id) & idaapi.AFL_USERTI == idaapi.AFL_USERTI
        sup_tinfoQ = internal.netnode.sup.has(mptr.id, idaapi.NSUP_TYPEINFO)
        has_typeinfo = sup_tinfoQ if sptr.props & getattr(idaapi, 'SF_FRAME', 0x40) else user_tinfoQ
        if has_typeinfo:
            ti = idaapi.tinfo_t()
            ok = idaapi.get_or_guess_member_tinfo2(mptr, ti) if idaapi.__version__ < 7.0 else idaapi.get_or_guess_member_tinfo(ti, mptr)

            # Now we need to attach the member name to our type. Hopefully it's not
            # mangled in some way that will need consideration if it's re-applied.
            ti_s = idaapi.print_tinfo('', 0, 0, 0, ti, utils.string.to(declaration.unmangled.parsable(aname) if aname else ''), '')
            res.setdefault('__typeinfo__', ti_s)
        return res
