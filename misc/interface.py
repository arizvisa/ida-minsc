"""
Interface module (internal)

This module wraps a number of features provided by IDA so that it can be
dumbed down a bit. This module is used internally and thus doesn't provide
anything that a user should use. Nonetheless, we document this for curious
individuals to attempt to understand this craziness.
"""

import six, builtins
import sys, logging, contextlib
import functools, operator, itertools
import collections, heapq, traceback, ctypes, math, codecs
import unicodedata as _unicodedata, string as _string, array as _array

import idaapi, internal, architecture

class typemap(object):
    """
    This namespace provides bidirectional conversion from IDA's types
    to something more pythonic. This namespace is actually pretty
    magical in that it dumbs down IDA's types for humans without
    needing a reference.

    Normally IDA defines types as flags and enumerations which require
    a user to know the correct ones in order to infer information about
    it. Although they can still do this, it's a lot more reasonable if
    we convert them into some weird python-like syntax.

    The syntax for types is fairly straight forward if one is familiar
    with the names that python exposes. Essentially the base type is
    a tuple of the format `(type, size)`. If `size` is not specified,
    then the size will be assumed to be the default word size for the
    current database. The `type` field is then any one of the python
    types such as ``int``, ``str``, ``chr``, ``float``, ``type``, or
    ``None``.

    These types have the following meanings:

        ``int`` or ``long`` - an integral
        ``chr`` - a character that is part of a string
        ``str`` - a type of string of a specific character width
        ``float`` - a floating point number
        ``type`` - a reference (pointer)
        ``None`` - alignment

    This can result in the describing of an IDA type and its size
    using a much simpler interface. Some examples can be:

        `int` - An integer with the default size
        `(int, 2)` - a 16-bit integer
        `(type, 4)` - a 32-bit referece (pointer)
        `(float, 4)` - a 16-bit floating point (ieee754 single)
        `(None, 16)` - aligned to 16 bytes
        `(str, 2)` - a 16-bit null-terminated string
        `(str, 4)` - a 32-bit null-terminated string
        `(str, 1, 4)` - an 8-bit character string with a 32-bit length prefix.
        `(str, 2, 2)` - an 16-bit character string with a 16-bit length prefix.
        `(str, 1, 0)` - an 8-bit character null-terminated string

    If an array needs to be represented, then one can simply wrap
    their type within a list. A few examples of this follows:

        `[int, 4]` - a 4 element array of default sized integers
        `[str, 9]` - an 8-bit string of 9 characters
        `[(int, 2), 3]` - a 3 element array of 16-bit integers
        `[(float, 8), 4]` - a 4 element array of 64-bit floating point numbers.
        `[type, 6]` - a 6 element array of references (pointers)
        `[(chr, 2), 7]` - a 7-element string of 16-bit characters
        `[str, 7]` - a 10-element string of 8-bit characters
        `[(str, 4), 2]` - a 2-element string of 32-bit characters

    These types are commonly associated with members of structures
    and thus can be used to quickly read or apply a type to a
    field within a structure.
    """
    MS_0TYPE, MS_1TYPE = idaapi.MS_0TYPE, idaapi.MS_1TYPE
    FF_MASKSIZE = idaapi.as_uint32(idaapi.DT_TYPE)  # Mask that select's the flag's size
    FF_MASK = FF_MASKSIZE | MS_0TYPE | MS_1TYPE     # Mask that select's the flag's repr

    # FIXME: Figure out how to update this to use/create an idaapi.tinfo_t()
    #        and also still remain backwards-compatible with the older idaapi.opinfo_t()

    ## IDA 6.95 types
    if idaapi.__version__ < 7.0:
        integermap = {
            (int,  1):(idaapi.byteflag(), -1), (int, 2):(idaapi.wordflag(), -1), (int,  3):(idaapi.tribyteflag(), -1),
            (int,  4):(idaapi.dwrdflag(), -1), (int, 8):(idaapi.qwrdflag(), -1), (int, 10):(idaapi.tbytflag(), -1),
            (int, 16):(idaapi.owrdflag(), -1),
        }
        if hasattr(idaapi, 'ywrdflag'):
            integermap[int, 32] = getattr(idaapi, 'ywrdflag')(), -1

        decimalmap = {
            (float,  4):(idaapi.floatflag(), -1),     (float, 8):(idaapi.doubleflag(), -1),
            (float, 10):(idaapi.packrealflag(), -1), (float, 12):(idaapi.packrealflag(), -1),
        }

        # we support either chr or str interchangeably
        stringmap = {
            chr:(idaapi.asciflag(), idaapi.ASCSTR_TERMCHR),
            str:(idaapi.asciflag(), idaapi.ASCSTR_TERMCHR),

            # null-terminated, char_t and wchar_t
            (str, 1): (idaapi.asciflag(), idaapi.ASCSTR_TERMCHR),
            (str, 2): (idaapi.asciflag(), idaapi.ASCSTR_UNICODE),

            (chr, 1): (idaapi.asciflag(), idaapi.ASCSTR_TERMCHR),
            (chr, 2): (idaapi.asciflag(), idaapi.ASCSTR_UNICODE),

            # variable-terminated, multiple-byte
            (str, 1, 0): (idaapi.asciflag(), idaapi.ASCSTR_TERMCHR),
            (str, 2, 0): (idaapi.asciflag(), idaapi.ASCSTR_UNICODE),
            (str, 1, 1): (idaapi.asciflag(), idaapi.ASCSTR_PASCAL),
            (str, 1, 2): (idaapi.asciflag(), idaapi.ASCSTR_LEN2),
            (str, 2, 2): (idaapi.asciflag(), idaapi.ASCSTR_ULEN2),
            (str, 2, 4): (idaapi.asciflag(), idaapi.ASCSTR_ULEN4),

            (chr, 1, 0): (idaapi.asciflag(), idaapi.ASCSTR_TERMCHR),
            (chr, 2, 0): (idaapi.asciflag(), idaapi.ASCSTR_UNICODE),
            (chr, 1, 1): (idaapi.asciflag(), idaapi.ASCSTR_PASCAL),
            (chr, 1, 2): (idaapi.asciflag(), idaapi.ASCSTR_LEN2),
            (chr, 2, 2): (idaapi.asciflag(), idaapi.ASCSTR_ULEN2),
            (chr, 2, 4): (idaapi.asciflag(), idaapi.ASCSTR_ULEN4),
        }

        if hasattr(builtins, 'unichr'):
            stringmap.setdefault(builtins.unichr, (idaapi.asciflag(), idaapi.ASCSTR_UNICODE))
        if hasattr(builtins, 'unicode'):
            stringmap.setdefault(builtins.unicode, (idaapi.asciflag(), idaapi.ASCSTR_UNICODE))

        ptrmap = { (type, sz) : (idaapi.offflag() | flg, 0) for (_, sz), (flg, _) in integermap.items() }
        #nonemap = { (None, pow(2, sz)) :(idaapi.alignflag(), -1) for sz in builtins.range(16) }
        nonemap = { None : (idaapi.alignflag(), -1) }

    ## IDA 7.0 types
    else:
        integermap = {
            (int,  1):(idaapi.byte_flag(), -1),  (int, 2):(idaapi.word_flag(), -1),
            (int,  4):(idaapi.dword_flag(), -1), (int, 8):(idaapi.qword_flag(), -1), (int, 10):(idaapi.tbyte_flag(), -1),
            (int, 16):(idaapi.oword_flag(), -1),
        }
        if hasattr(idaapi, 'yword_flag'):
            integermap[int, 32] = getattr(idaapi, 'yword_flag')(), -1

        decimalmap = {
            (float,  4):(idaapi.float_flag(), -1),    (float,  8):(idaapi.double_flag(), -1),
            (float, 10):(idaapi.packreal_flag(), -1), (float, 12):(idaapi.packreal_flag(), -1),
        }

        # we support either chr or str interchangeably
        stringmap = {
            chr:(idaapi.strlit_flag(), idaapi.STRTYPE_C),
            str:(idaapi.strlit_flag(), idaapi.STRTYPE_C),

            # null-terminated, multiple-byte
            (str, 1): (idaapi.strlit_flag(), idaapi.STRLYT_TERMCHR << idaapi.STRLYT_SHIFT | idaapi.STRWIDTH_1B),
            (str, 2): (idaapi.strlit_flag(), idaapi.STRLYT_TERMCHR << idaapi.STRLYT_SHIFT | idaapi.STRWIDTH_2B),
            (str, 4): (idaapi.strlit_flag(), idaapi.STRLYT_TERMCHR << idaapi.STRLYT_SHIFT | idaapi.STRWIDTH_4B),

            (chr, 1): (idaapi.strlit_flag(), idaapi.STRLYT_TERMCHR << idaapi.STRLYT_SHIFT | idaapi.STRWIDTH_1B),
            (chr, 2): (idaapi.strlit_flag(), idaapi.STRLYT_TERMCHR << idaapi.STRLYT_SHIFT | idaapi.STRWIDTH_2B),
            (chr, 4): (idaapi.strlit_flag(), idaapi.STRLYT_TERMCHR << idaapi.STRLYT_SHIFT | idaapi.STRWIDTH_4B),

            # variable-terminated, multiple-byte
            (str, 1, 0): (idaapi.strlit_flag(), idaapi.STRLYT_TERMCHR << idaapi.STRLYT_SHIFT | idaapi.STRWIDTH_1B),
            (str, 1, 1): (idaapi.strlit_flag(), idaapi.STRLYT_PASCAL1 << idaapi.STRLYT_SHIFT | idaapi.STRWIDTH_1B),
            (str, 1, 2): (idaapi.strlit_flag(), idaapi.STRLYT_PASCAL2 << idaapi.STRLYT_SHIFT | idaapi.STRWIDTH_1B),
            (str, 1, 4): (idaapi.strlit_flag(), idaapi.STRLYT_PASCAL4 << idaapi.STRLYT_SHIFT | idaapi.STRWIDTH_1B),
            (str, 2, 0): (idaapi.strlit_flag(), idaapi.STRLYT_TERMCHR << idaapi.STRLYT_SHIFT | idaapi.STRWIDTH_2B),
            (str, 2, 1): (idaapi.strlit_flag(), idaapi.STRLYT_PASCAL1 << idaapi.STRLYT_SHIFT | idaapi.STRWIDTH_2B),
            (str, 2, 2): (idaapi.strlit_flag(), idaapi.STRLYT_PASCAL2 << idaapi.STRLYT_SHIFT | idaapi.STRWIDTH_2B),
            (str, 2, 4): (idaapi.strlit_flag(), idaapi.STRLYT_PASCAL4 << idaapi.STRLYT_SHIFT | idaapi.STRWIDTH_2B),
            (str, 4, 0): (idaapi.strlit_flag(), idaapi.STRLYT_TERMCHR << idaapi.STRLYT_SHIFT | idaapi.STRWIDTH_4B),
            (str, 4, 1): (idaapi.strlit_flag(), idaapi.STRLYT_PASCAL1 << idaapi.STRLYT_SHIFT | idaapi.STRWIDTH_4B),
            (str, 4, 2): (idaapi.strlit_flag(), idaapi.STRLYT_PASCAL2 << idaapi.STRLYT_SHIFT | idaapi.STRWIDTH_4B),
            (str, 4, 4): (idaapi.strlit_flag(), idaapi.STRLYT_PASCAL4 << idaapi.STRLYT_SHIFT | idaapi.STRWIDTH_4B),

            (chr, 1, 0): (idaapi.strlit_flag(), idaapi.STRLYT_TERMCHR << idaapi.STRLYT_SHIFT | idaapi.STRWIDTH_1B),
            (chr, 1, 1): (idaapi.strlit_flag(), idaapi.STRLYT_PASCAL1 << idaapi.STRLYT_SHIFT | idaapi.STRWIDTH_1B),
            (chr, 1, 2): (idaapi.strlit_flag(), idaapi.STRLYT_PASCAL2 << idaapi.STRLYT_SHIFT | idaapi.STRWIDTH_1B),
            (chr, 1, 4): (idaapi.strlit_flag(), idaapi.STRLYT_PASCAL4 << idaapi.STRLYT_SHIFT | idaapi.STRWIDTH_1B),
            (chr, 2, 0): (idaapi.strlit_flag(), idaapi.STRLYT_TERMCHR << idaapi.STRLYT_SHIFT | idaapi.STRWIDTH_2B),
            (chr, 2, 1): (idaapi.strlit_flag(), idaapi.STRLYT_PASCAL1 << idaapi.STRLYT_SHIFT | idaapi.STRWIDTH_2B),
            (chr, 2, 2): (idaapi.strlit_flag(), idaapi.STRLYT_PASCAL2 << idaapi.STRLYT_SHIFT | idaapi.STRWIDTH_2B),
            (chr, 2, 4): (idaapi.strlit_flag(), idaapi.STRLYT_PASCAL4 << idaapi.STRLYT_SHIFT | idaapi.STRWIDTH_2B),
            (chr, 4, 0): (idaapi.strlit_flag(), idaapi.STRLYT_TERMCHR << idaapi.STRLYT_SHIFT | idaapi.STRWIDTH_4B),
            (chr, 4, 1): (idaapi.strlit_flag(), idaapi.STRLYT_PASCAL1 << idaapi.STRLYT_SHIFT | idaapi.STRWIDTH_4B),
            (chr, 4, 2): (idaapi.strlit_flag(), idaapi.STRLYT_PASCAL2 << idaapi.STRLYT_SHIFT | idaapi.STRWIDTH_4B),
            (chr, 4, 4): (idaapi.strlit_flag(), idaapi.STRLYT_PASCAL4 << idaapi.STRLYT_SHIFT | idaapi.STRWIDTH_4B),
        }
        if hasattr(builtins, 'unichr'):
            stringmap.setdefault(builtins.unichr, (idaapi.strlit_flag(), idaapi.STRTYPE_C_16))
        if hasattr(builtins, 'unicode'):
            stringmap.setdefault(builtins.unicode, (idaapi.strlit_flag(), idaapi.STRTYPE_C_16))

        ptrmap = { (type, sz) : (idaapi.off_flag() | flg, 0) for (_, sz), (flg, _) in integermap.items() }
        #nonemap = { (None, pow(2, sz)) : (idaapi.align_flag(), -1) for sz in builtins.range(16) }
        nonemap = { None : (idaapi.align_flag(), -1) }

    # Force all the flags for each lookup table to be 32-bit.
    s = f = v = 0
    integermap = {s : (idaapi.as_uint32(f), v) for s, (f, v) in integermap.items()}
    decimalmap = {s : (idaapi.as_uint32(f), v) for s, (f, v) in decimalmap.items()}
    stringmap = {s : (idaapi.as_uint32(f), v) for s, (f, v) in stringmap.items()}
    ptrmap = {s : (idaapi.as_uint32(f), v) for s, (f, v) in ptrmap.items()}
    nonemap = {s : (idaapi.as_uint32(f), v) for s, (f, v) in nonemap.items()}
    del s, (f, v)

    # Generate the lookup table for looking up the correct tables for a given type.
    typemap = {
        int:integermap, float:decimalmap,
        str:stringmap, chr:stringmap,
        type:ptrmap, None:nonemap,
    }
    if hasattr(builtins, 'long'): typemap.setdefault(builtins.long, integermap)
    if hasattr(builtins, 'unicode'): typemap.setdefault(builtins.unicode, stringmap)
    if hasattr(builtins, 'unichr'): typemap.setdefault(builtins.unichr, stringmap)

    # Invert our lookup tables so that we can find the correct python types for the
    # IDAPython flags that are defined. We define s, f, and _ so that we can guarantee
    # their deletion later. Although this isn't the case here since we've already
    # assigned the iterators for each loop, the variables won't be scoped if their
    # loop doesn't iterate.. resulting in an exception if we try to delete them.
    inverted, s = _, f = _, _ = {}, None
    for s, (f, _) in integermap.items():
        inverted[f & FF_MASKSIZE] = s
    for s, (f, _) in decimalmap.items():
        inverted[f & FF_MASKSIZE] = s
    for s, (f, _) in stringmap.items():
        if (next(iter(s)) if isinstance(s, internal.types.tuple) else s) in {str}: # prioritize `str`
            inverted[f & FF_MASKSIZE, _] = s
        continue

    # Default size for alignflag is 1, since alignment is not actually a type and
    # isn't understood by the disassembler when applied to a member.
    # XXX: still would be nice if we could somehow connect this to NALT_ALIGN,
    #      and use the size parameter as the actual alignment size...
    for s, (f, _) in nonemap.items():
        inverted[f & FF_MASKSIZE] = s, 1

    # Add all the available flag types to support all available pointer types.
    for s, (f, _) in ptrmap.items():
        inverted[f & FF_MASK] = s
        inverted[f & FF_MASK & ~MS_0TYPE] = s
        inverted[f & FF_MASK & ~MS_1TYPE] = s
    del s, (f, [[[[_]]]]) # let's pick the worst possible syntax

    # FIXME: this is a hack for dealing with structures that
    #        have the flag set but aren't actually structures..
    inverted[idaapi.FF_STRUCT if hasattr(idaapi, 'FF_STRUCT') else idaapi.FF_STRU] = (int, 1)

    # refinfo map for the sizes (IDA 6.9 uses the same names)
    refinfomap = {
        (type, 1) : idaapi.REF_OFF8,    (type, 2) : idaapi.REF_OFF16,
        (type, 4) : idaapi.REF_OFF32,   (type, 8) : idaapi.REF_OFF64,
    }

    # Assign the default values for the processor that was selected for the database.
    @classmethod
    def __newprc__(cls, pnum):
        info = idaapi.get_inf_structure()
        bits = 64 if info.is_64bit() else 32 if info.is_32bit() else None
        if bits is None: return

        typemap.integermap[None] = typemap.integermap[int, bits // 8]
        typemap.decimalmap[None] = typemap.decimalmap[float, bits // 8]
        typemap.ptrmap[None] = typemap.ptrmap[type, bits // 8]
        typemap.stringmap[None] = typemap.stringmap[str]

    @classmethod
    def __ev_newprc__(cls, pnum, keep_cfg):
        return cls.__newprc__(pnum)

    @classmethod
    def __nw_newprc__(cls, nw_code, is_old_database):
        pnum = idaapi.ph_get_id()
        return cls.__newprc__(pnum)

    @classmethod
    def dissolve(cls, flag, typeid, size, offset=None):
        '''Convert the specified `flag`, `typeid`, and `size` into a pythonic type at the optional `offset`.'''
        FF_STRUCT = idaapi.FF_STRUCT if hasattr(idaapi, 'FF_STRUCT') else idaapi.FF_STRU
        dtype, dsize = flag & cls.FF_MASK, flag & cls.FF_MASKSIZE
        sf = -1 if flag & idaapi.FF_SIGN == idaapi.FF_SIGN else +1
        Fstring_encoding = idaapi.set_str_encoding_idx if hasattr(idaapi, 'set_str_encoding_idx') else lambda strtype, encoding_idx: (strtype & 0xffffff) | (encoding_idx << 24)
        strtype = typeid if typeid is None else typeid & Fstring_encoding(0xfffffff, 0)

        # Check if the dtype's size field (dsize) is describing a structure and
        # verify that our type-id is an integer so that we know that we need to
        # figure out the structure's size. We also do an explicit check if the type-id
        # is a structure because in some cases, IDA will forget to set the FF_STRUCT
        # flag but still assign the structure type-id to a union member.
        if (dsize == FF_STRUCT and isinstance(typeid, internal.types.integer)) or (typeid is not None and internal.structure.has(typeid)):
            t = internal.structure.new(typeid, 0 if offset is None else offset)

            # grab the size, and check it it's a variable-length struct so we can size it.
            sz, variableQ = t.size, t.ptr.props & getattr(idaapi, 'SF_VAR', 1)
            return t if sz == size else (t, size) if variableQ else [t, size // sz]

        # Verify that we actually have the datatype mapped and that we can look it up.
        if all(item not in cls.inverted for item in [dsize, dtype, (dtype, typeid), (dtype, strtype)]):
            raise internal.exceptions.InvalidTypeOrValueError(u"{:s}.dissolve({!r}, {!r}, {!r}) : Unable to locate a pythonic type that matches the specified flag.".format('.'.join([__name__, cls.__name__]), dtype, typeid, size))

        # Now that we know the datatype exists, extract the actual type (dtype)
        # and the type's size (dsize) from the inverted map while giving priority
        # to the type. This way we're checking the dtype for pointers (references)
        # and then only afterwards do we fall back to depending on the size.
        item = cls.inverted[dtype] if dtype in cls.inverted else cls.inverted[dtype, typeid] if (dtype, typeid) in cls.inverted else cls.inverted[dtype, strtype] if (dtype, strtype) in cls.inverted else cls.inverted[dsize]

        # If it's not a tuple, then it's not a "real" type and we only need the size.
        if not isinstance(item, tuple):
            return [item, size]

        # If it's got a length, then we can just use it.
        elif len(item) == 2:
            t, sz = item

        # If our tuple contains extra information (a string), then hack that in.
        else:
            t, width, length = item
            reduced = item if length > 0 else (t, width) if width > 1 else t

            # XXX: IDA includes the length in the actual count if we're being
            #      assigned to a structure but not within the database. So, we
            #      ignore the correct calculation (which makes the python type
            #      look inaccurate, but it represents the number of characters
            #      that fit within the prefix) and adjust it in the database module.

            #count = max(0, size - length) // width
            count = size // width
            return [reduced, count] if any([count > 1, size == 0]) else reduced if length > 0 or width > 1 else str

        # If the datatype size is not an integer, then we need to calculate the
        # size ourselves using the size parameter we were given and the element
        # size of the datatype as determined by the flags (DT_TYPE | MS_CLS).
        if not isinstance(sz, internal.types.integer):
            count = size // idaapi.get_data_elsize(idaapi.BADADDR, flag, idaapi.opinfo_t())
            return [t, count] if count > 1 else t

        # If we received an alignment type, then we need to specially handle this
        # since None always implies a single-byte regardless of the element size.
        elif t is None:
            return [t, size]

        # If the array is exactly one element, then we return a single element
        # which is represented by a tuple composed of the python type, and the
        # actual byte size of the datatype. Otherwise, we just return an array.
        element, count = sz * sf, size // sz if sz else 0
        if count == 1:
            return t, element
        return [(t, element), count]

    @classmethod
    def resolve(cls, pythonType):
        '''Convert the provided `pythonType` into IDA's `(flag, typeid, size)`.'''
        struc_flag = idaapi.struflag if idaapi.__version__ < 7.0 else idaapi.stru_flag

        sz, count = None, 1

        # If we were given a pythonic-type that's a tuple, then we know that this
        # is actually an atomic type that has its flag within our typemap. We'll
        # first use the type the user gave us to find the actual table containg
        # the sizes we want to look up, and then we extract the flag and typeid
        # from the table that we determined.
        if isinstance(pythonType, ().__class__) and not isinstance(next(iter(pythonType)), (idaapi.struc_t, internal.structure.structure_t)):
            table = cls.typemap[builtins.next(item for item in pythonType)]

            #t, sz = pythonType
            #table = cls.typemap[t] if not isinstance(t, internal.types.tuple) else cls.typemap[t[0]]
            #(t, sz), count = (pythonType, 1) if len(pythonType) == 2 else ((pythonType[0], pythonType), 1)
            if pythonType in table:
                flag, typeid = table[pythonType]
                t, width, length = pythonType if len(pythonType) == 3 else pythonType + (0,)
                return flag, typeid, width + length

            (t, sz), count = pythonType, 1
            table = table[abs(sz)]

        # If we were given a pythonic-type that's a list, then we know that this
        # is an array of some kind. We extract the count from the second element
        # of the list, but then we'll need to recurse into ourselves in order to
        # figure out the actual flag, type-id, and size of the type that we were
        # given by the first element of the list.
        elif isinstance(pythonType, internal.types.list):
            res, count = pythonType
            flag, typeid, sz = cls.resolve(res)

        # If our pythonic-type is an actual structure_t, then obviously this
        # type is representing a structure. We know how to create the structure
        # flag, but we'll need to extract the type-id and the structure's size
        # from the properties of the structure that we were given.
        elif isinstance(pythonType, internal.structure.structure_t):
            flag, typeid, sz = struc_flag(), pythonType.id, pythonType.size

        # If our pythonic-type is an idaapi.struc_t, then we need to do
        # pretty much the exact same thing that we did for the structure_t
        # and extract both its type-id and size.
        elif isinstance(pythonType, idaapi.struc_t):
            flag, typeid, sz = struc_flag(), pythonType.id, idaapi.get_struc_size(pythonType)

        # if we got here with a tuple, then that's because we're using a variable-length
        # structure...which really means the size is forced.
        elif isinstance(pythonType, internal.types.tuple):
            t, sz = pythonType
            sptr = t.ptr if isinstance(t, internal.structure.structure_t) else t
            flag, typeid = struc_flag(), sptr.id

            # if we're not a variable-length structure, then this pythonic type isn't
            # valid. we still don't error out, though, and we just correct the size.
            if not sptr.props & getattr(idaapi, 'SF_VAR', 1):
                sz = idaapi.get_struc_size(sptr)

        # Anything else should be the default value that we're going to have to
        # look up. We start by using the type to figure out the correct table,
        # and then we grab the flags and type-id from the None key for the
        # pythonType. This should give us the default type information for the
        # current database and architecture.
        else:
            table = cls.typemap[pythonType]
            flag, typeid = table[None]

            # Construct an opinfo_t with the type-id that was returned, and then
            # calculate the correct size for the value returned by our table.
            opinfo, typeid = idaapi.opinfo_t(), idaapi.BADADDR if typeid < 0 else typeid
            opinfo.tid = typeid
            return flag, typeid, idaapi.get_data_elsize(idaapi.BADADDR, flag, opinfo)

        # Now we can return the flags, type-id, and the total size that IDAPython
        # uses when describing a type. We also check if our size is negative
        # because then we'll need to update the flags with the FF_SIGN flag in
        # order to describe the correct type requested by the user.
        typeid = idaapi.BADADDR if typeid < 0 else typeid
        return flag | (idaapi.FF_SIGN if sz < 0 else 0), typeid, abs(sz) * count

    @classmethod
    def update_refinfo(cls, identifier, flag):
        '''This updates the refinfo for the given `identifer` according to the provided `flag`.'''
        return address.update_refinfo(identifier, flag)

    @classmethod
    def size(cls, pythonType):
        '''Return the size of the provided `pythonType` discarding the array length if one was provided.'''
        structure = sys.modules.get('structure', __import__('structure'))

        # If we were given a list (for an array), then unpack it since
        # its length is entirely irrelevant to us.
        if isinstance(pythonType, internal.types.list):
            element, _ = [item for item in itertools.chain(pythonType, 2 * [0])][:2]
            return cls.size(element) if len(pythonType) == 2 else 0

        # If it's a tuple, then we can just unpack our size from the type and then return it.
        if isinstance(pythonType, internal.types.tuple):
            _, size, _ = [item for item in itertools.chain(pythonType, 3 * [0])][:3]
            return max(0, size) if isinstance(size, internal.types.integer) and len(pythonType) in {2, 3} else 0

        # If it's one of our structure types, then we can extract their sptr and use it.
        if isinstance(pythonType, (idaapi.struc_t, structure.structure_t)):
            sptr = pythonType if isinstance(pythonType, idaapi.struc_t) else pythonType.ptr
            return idaapi.get_struc_size(sptr)

        # Otherwise, we need to do a default type lookup to get the number of bytes.
        opinfo, table = idaapi.opinfo_t(), cls.typemap.get(pythonType, {}) if getattr(pythonType, '__hash__', None) else {}
        flag, typeid = table.get(None, (-1, -1))
        opinfo.tid = idaapi.BADADDR if typeid < 0 else typeid
        return idaapi.get_data_elsize(idaapi.BADADDR, flag, opinfo) if None in table else 0

class string(object):
    """
    This namespace provides basic utilities for interacting with the string
    type within the disassembler. A string type is an encoded 32-bit integer
    that consists of the string encoding, two terminal characters, and the
    width and prefix length which is interpreted as a bitmask in newer versions
    of the disassembler and an enumeration in older versions.
    """

    # tables for determining the width and length for each string type. these
    # tables are pre-shifted so that only a mask is needed to look things up.
    if idaapi.__version__ < 7.0:
        width = {
            idaapi.ASCSTR_TERMCHR: 1, idaapi.ASCSTR_PASCAL: 1, idaapi.ASCSTR_LEN2: 1, idaapi.ASCSTR_LEN4: 1,
            idaapi.ASCSTR_UNICODE: 2, idaapi.ASCSTR_ULEN2: 2, idaapi.ASCSTR_ULEN4: 2,
        }
        width_mask, width_shift = bytearray([idaapi.get_str_type_code(0xff), 0])

        length = {
            idaapi.ASCSTR_TERMCHR: 0, idaapi.ASCSTR_UNICODE: 0,
            idaapi.ASCSTR_PASCAL: 1,
            idaapi.ASCSTR_LEN2: 2, idaapi.ASCSTR_ULEN2: 2,
            idaapi.ASCSTR_LEN4: 4, idaapi.ASCSTR_ULEN4: 4,
        }
        length_mask, length_shift = bytearray([idaapi.get_str_type_code(0xff), 0])

        typecode = {
            (1, 0): idaapi.ASCSTR_TERMCHR,  (2, 0): idaapi.ASCSTR_UNICODE,
            (1, 1): idaapi.ASCSTR_PASCAL,
            (1, 2): idaapi.ASCSTR_LEN2,     (2, 2): idaapi.ASCSTR_ULEN2,
            (1, 4): idaapi.ASCSTR_LEN4,     (2, 4): idaapi.ASCSTR_ULEN4,
        }

    else:
        width = {
            idaapi.STRWIDTH_1B: 1,
            idaapi.STRWIDTH_2B: 2,
            idaapi.STRWIDTH_4B: 4,
        }
        width_mask, width_shift = getattr(idaapi, 'STRWIDTH_MASK', 0x03), 0

        length = {
            idaapi.STRLYT_TERMCHR << idaapi.STRLYT_SHIFT: 0,
            idaapi.STRLYT_PASCAL1 << idaapi.STRLYT_SHIFT: 1,
            idaapi.STRLYT_PASCAL2 << idaapi.STRLYT_SHIFT: 2,
            idaapi.STRLYT_PASCAL4 << idaapi.STRLYT_SHIFT: 4,
        }
        length_mask, length_shift = getattr(idaapi, 'STRLYT_MASK', 0xfc), getattr(idaapi, 'STRLYT_SHIFT', 2)

        typecode = {
            (1, 0): idaapi.STRLYT_TERMCHR << idaapi.STRLYT_SHIFT | idaapi.STRWIDTH_1B,
            (1, 1): idaapi.STRLYT_PASCAL1 << idaapi.STRLYT_SHIFT | idaapi.STRWIDTH_1B,
            (1, 2): idaapi.STRLYT_PASCAL2 << idaapi.STRLYT_SHIFT | idaapi.STRWIDTH_1B,
            (1, 4): idaapi.STRLYT_PASCAL4 << idaapi.STRLYT_SHIFT | idaapi.STRWIDTH_1B,

            (2, 0): idaapi.STRLYT_TERMCHR << idaapi.STRLYT_SHIFT | idaapi.STRWIDTH_2B,
            (2, 1): idaapi.STRLYT_PASCAL1 << idaapi.STRLYT_SHIFT | idaapi.STRWIDTH_2B,
            (2, 2): idaapi.STRLYT_PASCAL2 << idaapi.STRLYT_SHIFT | idaapi.STRWIDTH_2B,
            (2, 4): idaapi.STRLYT_PASCAL4 << idaapi.STRLYT_SHIFT | idaapi.STRWIDTH_2B,

            (4, 0): idaapi.STRLYT_TERMCHR << idaapi.STRLYT_SHIFT | idaapi.STRWIDTH_4B,
            (4, 1): idaapi.STRLYT_PASCAL1 << idaapi.STRLYT_SHIFT | idaapi.STRWIDTH_4B,
            (4, 2): idaapi.STRLYT_PASCAL2 << idaapi.STRLYT_SHIFT | idaapi.STRWIDTH_4B,
            (4, 4): idaapi.STRLYT_PASCAL4 << idaapi.STRLYT_SHIFT | idaapi.STRWIDTH_4B,
        }

    # mask and shifts for the other parts of a string (same on both versions)
    strterm1 = 0x0000ff00, 8
    strterm2 = 0x00ff0000, 16
    strencoding = 0xff000000, 24

    # general functions for interacting with a strtype.
    @classmethod
    def unpack(cls, strtype):
        '''Unpack the string type into its different parts as a tuple of `(width, length, terminals, encoding)`.'''
        mask, shift = cls.strterm1
        term1 = (strtype & mask) >> shift
        mask, shift = cls.strterm2
        term2 = (strtype & mask) >> shift
        mask, shift = cls.strencoding
        encoding = (strtype & mask) >> shift

        # combine our terminator characters into some bytes and then return what we've got.
        terminals = bytearray([term1, term2] if term2 else [term1]) # XXX: if term2 is '\0' then it is unused.
        return cls.width[strtype & cls.width_mask], cls.length[strtype & cls.length_mask], bytes(terminals), encoding

    @classmethod
    def pack(cls, width, length, terminals, encoding):
        '''Pack the string `width`, `length`, the `terminals`, and the `encoding` index into an integer representing the string type.'''
        STRENC_DEFAULT, STRENC_NONE = getattr(idaapi, 'STRENC_DEFAULT', 0), getattr(idaapi, 'STRENC_NONE', 0xFF)

        # figure out whether we were given the default encoding (None) or no
        # encoding (<0), and then encode it to the right place in the strtype.
        mask, shift = cls.strencoding
        index = STRENC_DEFAULT if encoding is None else STRENC_NONE if encoding < 0 else encoding
        encoding_idx = (index << shift) & mask

        # convert our terminal characters back into integers so that we can
        # encode them to the correct position in the strtype.
        term1, term2 = bytearray(itertools.islice(itertools.chain(terminals or b'', b'\0\0'), 2))
        mask, shift = cls.strterm1
        term1_idx = (term1 << shift) & mask
        mask, shift = cls.strterm1
        term2_idx = (term2 << shift) & mask

        # ...and then or what we were given back together.
        return functools.reduce(operator.or_, [encoding_idx, term1_idx, term2_idx], cls.typecode[width, length])

    @classmethod
    def check(cls, width, length):
        '''Return whether the given `width` and `length` are actually supported by the disassembler.'''
        return (width, length) in cls.typecode

    @classmethod
    def encoding(cls, name):
        '''Return the index for the encoding with the specified `name`.'''
        Fencoding_count = idaapi.get_encoding_qty if hasattr(idaapi, 'get_encoding_qty') else idaapi.get_encodings_count if hasattr(idaapi, 'get_encodings_count') else internal.utils.fconstant(0)

        # First look up the name to make sure that there's a codec for it.
        try: expected = codecs.lookup(name).name
        except LookupError: return -1

        # Iterate through all of the known encoding from the database and check
        # to see if they're one of our registered codecs. If so, then we can
        # verify that it matches the actual codec name that we're looking for.
        for idx in builtins.range(Fencoding_count()):
            name = idaapi.get_encoding_name(idx)
            if not name:
                continue

            # Trust that the codecs module will normalize the codec name.
            try: codec = codecs.lookup(name)
            except LookupError: continue

            # Do a case-insensitive comparison and return the index if it matches.
            if codec.name.upper() == expected.upper():
                return idx
            continue
        return -1

    @classmethod
    def codec(cls, width, index):
        '''Return the codec used for encoding or decoding a string of the specified `width` and encoding `index`.'''
        STRENC_DEFAULT, STRENC_NONE = getattr(idaapi, 'STRENC_DEFAULT', 0), getattr(idaapi, 'STRENC_NONE', 0xFF)
        Fencoding_count = idaapi.get_encoding_qty if hasattr(idaapi, 'get_encoding_qty') else idaapi.get_encodings_count if hasattr(idaapi, 'get_encodings_count') else internal.utils.fconstant(0)
        index = STRENC_DEFAULT if index is None else index

        # If there's no way to determine the encoding name, or we were given a default
        # encoding with no way to look up the index, then we need to bail.
        if not hasattr(idaapi, 'get_encoding_name') or (index == STRENC_DEFAULT and not hasattr(idaapi, 'get_default_encoding_idx')) or (isinstance(index, internal.types.string) and not hasattr(idaapi, 'add_encoding')):
            return None

        # If our index is actually a string (not an index), then we use it as a sign to
        # create the new encoding and recurse with our new index. Before we do this, however,
        # we need to verify that the encoding exists and bail if it doesn't.
        if isinstance(index, internal.types.string):
            upcased = index.upper()
            try: codecs.lookup(upcased)
            except LookupError: return None

            # Add the requested encoding to the database and recurse if it didn't error.
            index = idaapi.add_encoding(upcased)
            return None if index < 0 else cls.codec(width, index)

        # If we were given a default encoding, then we can use the width to figure out
        # the encoding. Otherwise we can just explicitly trust whatever name we were given.
        if index == STRENC_DEFAULT:
            encoding = idaapi.get_default_encoding_idx(width)

        # If it's not set, or the index is larger than the number of encodings, then
        # we bail because there's no way to figure out the encoding name here.
        elif index == STRENC_NONE or Fencoding_count() <= index:
            return None

        # Otherwise, it's trustable...but sorta, since get_encoding_name can still
        # return None, an empty string, or anything else that might be crazy.
        else:
            encoding = index

        # Now we should be able to get the encoding name from our index, so we can grab
        # it and then try to look up the encoding. If we failed, then we return none.
        name = idaapi.get_encoding_name(encoding)
        try:
            result = codecs.lookup(name or '')
        except LookupError:
            result = None
        return result

class prioritybase(object):
    result = type('result', (object,), {})
    CONTINUE = type('continue', (result,), {})()
    STOP = type('stop', (result,), {})()

    def __init__(self):
        self.__cache__ = collections.defaultdict(list)
        self.__disabled = {item for item in []}
        self.__traceback = {}

    def __iter__(self):
        '''Iterate through each target that is currently attached to this object.'''
        for target in self.__cache__:
            yield target
        return

    def __contains__(self, target):
        '''Return whether the specified `target` is currently attached to this object.'''
        return target in self.__cache__

    def __len__(self):
        '''Return the number of targets that are currently attached to this object.'''
        return len(self.__cache__)

    def __formatter__(self, target):
        raise NotImplementedError

    def attach(self, target):
        '''Intended to be called as a supermethod for the specified `target` that returns True or False along with the callable that should be applied to the hook.'''
        if target in self.__cache__:
            logging.warning(u"{:s}.attach({!r}) : Unable to attach to target ({:s}) due to it already being attached.".format('.'.join([__name__, self.__class__.__name__]), target, self.__formatter__(target)))
            return False, internal.utils.fidentity

        # Otherwise we need to ping the cache so that it creates a list, and then
        # we can return the callable that should be attached by the implementation.
        self.__cache__[target]
        return True, self.__apply__(target)

    def detach(self, target):
        '''Intended to be called as a supermethod for the specified `target` that removes the target from the cache.'''
        if target in self.__cache__:
            if len(self.__cache__[target]):
                logging.warning(u"{:s}.detach({!r}) : Unable to detach from target ({:s}) due to callable items still existing in its cache.".format('.'.join([__name__, self.__class__.__name__]), target, self.__formatter__(target)))
                return False
            self.__cache__.pop(target, None)
            return True
        logging.warning(u"{:s}.detach({!r}) : Unable to detach from target ({:s}) due to it not being attached.".format('.'.join([__name__, self.__class__.__name__]), target, self.__formatter__(target)))
        raise False

    def close(self):
        '''Disconnect from all of the targets that are currently attached'''
        ok, items = True, {item for item in self.__cache__}

        # Simply detach every available target one-by-one.
        for target in items:
            if not self.detach(target):
                logging.warning(u"{:s}.close() : Error trying to detach from the specified target ({:s}).".format('.'.join([__name__, self.__class__.__name__]), self.__formatter__(target)))
                ok = False
            continue
        return ok

    @property
    def available(self):
        '''Return all of the attached targets that can be either enabled or disabled.'''

        # This property is intended to be part of the public api and
        # thus it can reimplemented by one if considered necessary.

        result = {item for item in self.__cache__}
        return sorted(result)

    def list(self):
        '''List all of the targets that are available along with a description.'''

        # This property is intended to be part of the public api and
        # thus it can reimplemented by one if considered necessary.

        sorted = self.available
        formatted = {item : "{!s}:".format(item) for item in sorted}
        length = max(map(len, formatted.values())) if formatted else 0

        if formatted:
            for item in sorted:
                six.print_(u"{:<{:d}s} {:s}".format(formatted[item], length, self.__formatter__(item)))
            return
        six.print_(u"There are no available targets.")

    @property
    def disabled(self):
        '''Return all of the attached targets that are currently disabled.'''
        result = {item for item in self.__disabled}
        return sorted(result)
    @property
    def enabled(self):
        '''Return all of the attached targets that are currently enabled.'''
        result = {item for item in self.__cache__} - {item for item in self.__disabled}
        return sorted(result)

    def __repr__(self):
        cls, enabled = self.__class__, {item for item in self.__cache__} - {item for item in self.__disabled}

        # Extract the parameters from a function. This is just a
        # wrapper around utils.multicase.ex_args so we can extract
        # the names.
        def parameters(func):
            args, defaults, (star, starstar) = internal.utils.multicase.ex_args(func)
            for item in args:
                yield "{:s}={!s}".format(item, defaults[item]) if item in defaults else item
            if star:
                yield "*{:s}".format(star)
            if starstar:
                yield "**{:s}".format(starstar)
            return

        # Render the callable as something readable.
        def repr_callable(object, pycompat=internal.utils.pycompat):

            # If a method is passed to us, then we need to extract all
            # of the relevant components that describe it.
            if isinstance(object, (internal.types.method, internal.types.descriptor)):
                cls = pycompat.method.type(object)
                func = pycompat.method.function(object)
                module, name = func.__module__, pycompat.function.name(func)
                iterable = parameters(func)
                None if isinstance(object, internal.types.staticmethod) else next(iterable)
                return '.'.join([module, cls.__name__, name]), tuple(iterable)

            # If our object is a function-type, then it's easy to grab.
            elif isinstance(object, internal.types.function):
                module, name = object.__module__, pycompat.function.name(object)
                iterable = parameters(object)
                return '.'.join([module, name]), tuple(iterable)

            # If it's still callable, then this is likely a class.
            elif callable(object):
                symbols, module, name = object.__dict__, object.__module__, object.__name__
                cons = symbols.get('__init__', symbols.get('__new__', None))
                iterable = parameters(cons) if cons else []
                next(iterable)
                return '.'.join([module, name]), tuple(iterable)

            # Otherwise, we have no idea what it is...
            return "{!r}".format(object), None

        # Unpack a prioritytuple into its components so we can describe it.
        def repr_prioritytuple(tuple):
            priority, callable = tuple
            name, args = repr_callable(callable)
            return priority, name, args

        # If there aren't any targets available, then return immediately.
        if not self.__cache__:
            return '\n'.join(["{!s}".format(cls), "...No targets are being used...".format(cls)])

        alignment_enabled = max(len(self.__formatter__(target)) for target in enabled) if enabled else 0
        alignment_disabled = max(len("{:s} (disabled)".format(self.__formatter__(target))) for target in self.__disabled) if self.__disabled else 0
        res = ["{!s}".format(cls)]

        # First gather all our enabled hooks.
        for target in sorted(enabled):
            items = self.__cache__[target]
            hooks = sorted([(priority, callable) for priority, callable in items], key=operator.itemgetter(0))
            items = ["{description:s}[{:+d}]".format(priority, description=name if args is None else "{:s}({:s})".format(name, ', '.join(args))) for priority, name, args in map(repr_prioritytuple, hooks)]
            res.append("{:<{:d}s} : {!s}".format(self.__formatter__(target), alignment_enabled, ' '.join(items) if items else '...nothing attached...'))

        # Now we can append all the disabled ones.
        for target in sorted(self.__disabled):
            items = self.__cache__[target]
            hooks = sorted([(priority, callable) for priority, callable in items], key=operator.itemgetter(0))
            items = ["{description:s}[{:+d}]".format(priority, description=name if args is None else "{:s}({:s})".format(name, ', '.join(args))) for priority, name, args in map(repr_prioritytuple, hooks)]
            res.append("{:<{:d}s} : {!s}".format("{:s} (disabled)".format(self.__formatter__(target)), alignment_disabled, ' '.join(items) if items else '...nothing attached...'))

        # And then return it to the caller.
        return '\n'.join(res)

    def enable(self, target):
        '''Enable any callables for the specified `target` that have been previously disabled.'''
        cls = self.__class__
        if target not in self.__cache__:
            logging.fatal(u"{:s}.enable({!r}) : The requested target ({:s}) is not attached. {:s}".format('.'.join([__name__, cls.__name__]), target, self.__formatter__(target), "Currently disabled targets are: {:s}".format(', '.join(map(self.__formatter__, self.__disabled))) if self.__disabled else 'There are no disabled targets that may be enabled.'))
            return False
        if target not in self.__disabled:
            logging.fatal(u"{:s}.enable({!r}) : The requested target ({:s}) is not disabled. {:s}".format('.'.join([__name__, cls.__name__]), target, self.__formatter__(target), "Currently disabled targets are: {:s}".format(', '.join(map(self.__formatter__, self.__disabled))) if self.__disabled else 'There are no disabled targets that may be enabled.'))
            return False

        # Always explicitly do what we're told...
        self.__disabled.discard(target)

        # But if there were no entries in the cache, then warn the user about it.
        if not len(self.__cache__[target]):
            logging.warning(u"{:s}.enable({!r}) : The requested target ({:s}) does not have any callables to enable.".format('.'.join([__name__, cls.__name__]), target, self.__formatter__(target)))
            return True
        return True

    def disable(self, target):
        '''Disable execution of all the callables for the specified `target`.'''
        cls, enabled = self.__class__, {item for item in self.__cache__} - self.__disabled
        if target not in self.__cache__:
            logging.fatal(u"{:s}.disable({!r}) : The requested target ({:s}) is not attached. {:s}".format('.'.join([__name__, cls.__name__]), target, self.__formatter__(target), "Currently enabled targets are: {:s}".format(', '.join(map(self.__formatter__, enabled))) if enabled else 'All targets have already been disabled.' if self.__disabled else 'There are no currently attached targets to disable.'))
            return False
        if target in self.__disabled:
            logging.warning(u"{:s}.disable({!r}) : The requested target ({:s}) has already been disabled. {:s}".format('.'.join([__name__, cls.__name__]), target, self.__formatter__(target), "Currently enabled targets are: {:s}".format(', '.join(map(self.__formatter__, enabled))) if enabled else 'All targets have already been disabled.'))
            return False
        self.__disabled.add(target)
        return True

    def add(self, target, callable, priority):
        '''Add the `callable` to the queue for the specified `target` with the given `priority`.'''
        if not builtins.callable(callable):
            cls, format = self.__class__, "{:+d}".format if isinstance(priority, internal.types.integer) else "{!r}".format
            raise TypeError(u"{:s}.add({!r}, {!s}, priority={!r}) : Refusing to add a non-callable ({!s}) for the requested target with the given priority ({!r}).".format('.'.join([__name__, cls.__name__]), target, callable, priority, callable, format(priority)))
        elif not isinstance(priority, internal.types.integer):
            cls, format = self.__class__, "{:+d}".format if isinstance(priority, internal.types.integer) else "{!r}".format
            raise TypeError(u"{:s}.add({!r}, {!s}, priority={!r}) : Refusing to add a callable ({!s}) for the requested target with a non-integer priority ({!r}).".format('.'.join([__name__, cls.__name__]), target, callable, priority, callable, format(priority)))

        # attach to the requested target if possible
        if target not in self.__cache__:
            cls, format = self.__class__, "{:+d}".format if isinstance(priority, internal.types.integer) else "{!r}".format
            raise NameError(u"{:s}.add({!r}, {!s}, priority={:s}) : The requested target ({:s}) is not attached. {:s}".format('.'.join([__name__, cls.__name__]), target, callable, format(priority), self.__formatter__(target), "Currently attached targets are: {:s}".format(', '.join(map(self.__formatter__, self.__cache__))) if self.__cache__ else 'There are no currently attached targets to add to.'))

        # discard any callables already attached to the specified target
        self.discard(target, callable)

        # add the callable to our priority queue
        queue = self.__cache__[target]
        heapq.heappush(queue, internal.utils.priority_tuple(priority, callable))

        # preserve a backtrace so we can track where our callable is at
        self.__traceback[(target, callable)] = traceback.extract_stack()[:-1]
        return True

    def get(self, target):
        '''Return all of the callables that are attached to the specified `target`.'''
        if target not in self.__cache__:
            cls = self.__class__
            raise NameError(u"{:s}.get({!r}) : The requested target ({:s}) is not attached. {:s}".format('.'.join([__name__, cls.__name__]), target, self.__formatter__(target), "Currently attached targets are: {:s}".format(', '.join(map(self.__formatter__, self.__cache__))) if self.__cache__ else 'There are no currently attached targets to get from.'))

        # Return the callables attached to the specified target.
        res = self.__cache__[target]
        return tuple(callable for _, callable in res)

    def pop(self, target, index):
        '''Pop the item at the specified `index` from the given `target`.'''
        if target not in self.__cache__:
            cls, format = self.__class__, "{:d}".format if isinstance(index, internal.types.integer) else "{!r}".format
            raise NameError(u"{:s}.pop({!r}, {:d}) : The requested target ({:s}) is not attached. Currently attached targets are {:s}.".format('.'.join([__name__, cls.__name__]), target, format(index), self.__formatter__(target), "Currently attached targets are: {:s}".format(', '.join(map(self.__formatter__, self.__cache__))) if self.__cache__ else 'There are no targets currently attached to pop from.'))
        state = []

        # Iterate through the cache for the specified target and collect
        # each callable so we can figure out which one to remove.
        for (priority, F) in self.__cache__[target][:]:
            state.append((priority, F))

        # Pop off the result the user requested, and then combine our
        # state back into the cache we took it from.
        item = state.pop(index)
        if state:
            self.__cache__[target][:] = [internal.utils.priority_tuple(*item) for item in state]

        # Otherwise our target will need to be emptied.
        else:
            self.__cache__[target][:] = []

        # Now we can return whatever it was they removed.
        priority, result = item
        return result

    def discard(self, target, callable):
        '''Discard the `callable` from our priority queue for the specified `target`.'''
        if target not in self.__cache__:
            return False
        state = []

        # Filter through our cache for the specified target, and collect
        # each callable except for the one the user provided.
        found = 0
        for index, (priority, F) in enumerate(self.__cache__[target][:]):
            if F == callable:
                found += 1
                continue
            state.append((priority, F))

        # If we aggregated some items, then replace our cache with everything
        # except for the item the user discarded.
        if state:
            self.__cache__[target][:] = [internal.utils.priority_tuple(*item) for item in state]

        # Otherwise we found nothing and we should just empty the target.
        else:
            self.__cache__[target][:] = []

        return True if found else False

    def remove(self, target, priority):
        '''Remove the first callable from the specified `target` that has the provided `priority`.'''
        if target not in self.__cache__:
            cls, format = self.__class__, "{:+d}".format if isinstance(priority, internal.types.integer) else "{!r}".format
            raise NameError(u"{:s}.remove({!r}, {:s}) : The requested target ({:s}) is not attached. {:s}".format('.'.join([__name__, cls.__name__]), target, format(priority), self.__formatter__(target), "Currently attached targets are: {:s}".format(', '.join(map(self.__formatter__, self.__cache__))) if self.__cache__ else 'There are no targets currently attached to remove from.'))
        state, table = [], {}

        # Iterate through our cache for the specified target and save
        # both the state and the index of every single priority.
        for index, (prio, F) in enumerate(self.__cache__[target][:]):
            state.append((prio, F))
            table.setdefault(prio, []).append(index)

        # Before we do anything, we need to ping the priority we're searching for
        # in the table and then we grab the first index for the given priority.
        if priority not in table:
            cls, format = self.__class__, "{:+d}".format if isinstance(priority, internal.types.integer) else "{!r}".format
            raise internal.exceptions.ItemNotFoundError(u"{:s}.remove({!r}, {:s}) : Unable to locate a callable with the specific priority ({:s}).".format('.'.join([__name__, cls.__name__]), target, format(prio), format(prio)))
        index = table[priority].pop(0)

        # We now can pop the index directly out of the state. Afterwards, we
        # need to shove our state back into the cache for the target.
        item = state.pop(index)
        if state:
            self.__cache__[target][:] = [internal.utils.priority_tuple(*item) for item in state]

        # If our state is empty, then we go ahead and empty the target.
        else:
            self.__cache__[target][:] = []

        # We have an item that we can now return.
        priority, result = item
        return result

    def __apply__(self, target):
        '''Return a closure that will execute all of the callables for the specified `target`.'''

        ## Define the closure that we'll hand off to attach
        def closure(*parameters):
            if target not in self.__cache__ or target in self.__disabled:
                return

            # Iterate through our priorityqueue extracting each callable and
            # executing it with the parameters we received
            hookq, captured = self.__cache__[target][:], None
            for priority, callable in heapq.nsmallest(len(hookq), hookq, key=operator.attrgetter('priority')):
                logging.debug(u"{:s}.callable({:s}) : Dispatching parameters ({:s}) to callable ({!s}) with priority ({:+d}).".format('.'.join([__name__, self.__class__.__name__]), ', '.join(map("{!r}".format, parameters)), ', '.join(map("{!r}".format, parameters)), callable, priority))

                try:
                    result = callable(*parameters)

                # if we caught an exception, then inform the user about it and stop processing our queue
                except:
                    cls = self.__class__
                    bt = traceback.format_list(self.__traceback[target, callable])
                    current = str().join(traceback.format_exception(*sys.exc_info()))

                    format = functools.partial(u"{:s}.callable({:s}) : {:s}".format, '.'.join([__name__, cls.__name__]), ', '.join(map("{!r}".format, parameters)))
                    logging.fatal(format(u"Callable for {:s} with priority ({:+d}) raised an exception while executing {!s}.".format(self.__formatter__(target), priority, callable)))
                    logging.warning(format(u"Traceback ({:s} was attached at):".format(self.__formatter__(target))))
                    [ logging.warning(format(item)) for item in str().join(bt).split('\n') ]
                    [ logging.warning(format(item)) for item in current.split('\n') ]

                    result = self.STOP

                # Check if it's one of our valid return types. If we're being
                # asked to continue, then move onto the next one.
                if result == self.CONTINUE:
                    continue

                # If we're being asked to stop, then break the loop and terminate.
                elif result == self.STOP:
                    break

                # If we received an unexpected type, then throw up an exception.
                elif isinstance(result, self.result):
                    cls = self.__class__
                    raise internal.exceptions.InvalidTypeOrValueError(u"{:s}.callable({:s}) : Unable to determine the type of result ({!r}) returned from callable ({!s}).".format('.'.join([__name__, cls.__name__]), ', '.join(map("{!r}".format, parameters)), result, callable))

                # If there was no result, then just continue on like nothing happened.
                elif result is None:
                    continue

                # Otherwise we need to save what we got. If it was different, then
                # warn the user that someone is trying to interfere with results.
                elif captured is None:
                    cls = self.__class__
                    logging.info(u"{:s}.callable({:s}) : Captured a result ({!s}) for target {:s} from callable ({!s}) to return to caller.".format('.'.join([__name__, cls.__name__]), ', '.join(map("{!r}".format, parameters)), result, self.__formatter__(target), callable))

                elif result != captured:
                    cls = self.__class__
                    logging.warning(u"{:s}.callable({:s}) : Captured a result ({!s}) for target {:s} from callable ({!s}) that is different than the previous ({!s}).".format('.'.join([__name__, cls.__name__]), ', '.join(map("{!r}".format, parameters)), result, self.__formatter__(target), callable, captured))

                # Assign the captured return code now that we know what it is.
                captured = captured if result is None else result
            return captured

        # That's it!
        return closure

class priorityhook(prioritybase):
    """
    Helper class for allowing one to apply a number of hooks to the
    different hook points within IDA.
    """
    def __init__(self, klass, mapping={}):
        '''Construct an instance of a priority hook with the specified IDA hook type which can be one of ``idaapi.*_Hooks``.'''
        super(priorityhook, self).__init__()

        # stash away our hook class and instantiate a dummy instance of
        # the class that we're going to be attaching our hooks to.
        self.__klass__, self.object = klass, klass()

        # enumerate all of the attachable methods, and create a dictionary
        # that will contain the methods that are currently attached.
        self.__attachable__ = { name for name in klass.__dict__ if not name.startswith('__') and name not in {'hook', 'unhook', 'thisown'} }
        self.__attached__ = {}

        # stash away our mapping of supermethods so that we can return the
        # right one when we're asked to generate them for __supermethod__.
        self.__mapping__ = mapping

        # now that we have everything setup, connect our instance so that
        # when the user modifies it, the call to unhook() will succeed.
        self.object.hook()

    def __supermethod__(self, name):
        '''Generate a method that calls the super method specified by `name`.'''

        # This closure uses a cell (name) in order to generically determine
        # the correct supermethod. Implementors will have to figure out the
        # particular attribute name for the corresponding supermethod themselves
        # and so they'll need to hardcoded it in order to avoid us having to
        # inject the correct supermethod directly into their scope ourselves.
        def supermethod(self, *parameters, **keywords):
            cls = super(self.__class__, self)
            method = getattr(cls, name)
            return method(*parameters, **keywords)

        # Check the mapping of supermethods, and if one exists then return it
        # instead of our generic supermethod that was just defined.
        mapping = self.__mapping__
        return mapping.get(name, supermethod)

    def __formatter__(self, name):
        cls = self.__klass__
        return '.'.join([cls.__name__, name])

    @contextlib.contextmanager
    def __instance__(self):
        '''Return a dictionary upon context entry, and then attach its items to a new hook object upon context exit.'''
        klass, attributes = self.__klass__, {}

        # Check that our object was unhooked, and raise an exception if it
        # not. This way we don't tamper with any hooks that are in use.
        if not self.object.unhook():
            cls = self.__class__
            logging.warning(u"{:s}.__instance__() : Unable to disconnect the current instance ({!s}) during modification.".format('.'.join([__name__, cls.__name__]), self.object.__class__))

        # Now we need to yield the attributes to the caller for them to modify.
        yield attributes

        # Then we need to iterate through all of the attributes in order to
        # gather the items that we'll use to generate a closure.
        methods = {}
        for name, callable in attributes.items():
            locals = {}

            # Assign some parameters that we need to feed into our closure.
            locals['target'], locals['callable'] = name, callable
            locals['supermethod'] = self.__supermethod__(name)

            # Generate a closure that will later be converted into a method.
            def closure(locals):
                def method(instance, *args, **kwargs):
                    target, callable, supermethod = (locals[item] for item in ['target', 'callable', 'supermethod'])
                    result = callable(*args, **kwargs)

                    # If we didn't get a result to return, then just dispatch
                    # to the supermethod so that we don't interfere with anything.
                    if result is None:
                        return supermethod(instance, *args, **kwargs)

                    # Otherwise we return the code that was given to us.
                    logging.debug(u"{:s}.method({:s}) : Received a value ({!r}) to return from {!s} for {:s}.".format('.'.join([__name__, self.__class__.__name__]), self.__formatter__(target), result, callable, self.__formatter__(target)))
                    return result
                return method

            # We've generated the closure to use and so we can store it in
            # our dictionary that will be converted into methods.
            methods[name] = closure(locals)

        # Now we can use the methods we generated and stored in our dictionary to
        # create a new type and use it to instantiate a new hook object.
        cls = type(klass.__name__, (klass,), {attribute : callable for attribute, callable in methods.items()})
        instance = cls()

        # Then we just stash away our object and then install the hooks.
        self.object = instance
        if not instance.hook():
            logging.critical(u"{:s}.__instance__() : Unable to reconnect new instance ({!s}) during modification.".format('.'.join([__name__, cls.__name__]), instance.__class__))
        return

    @property
    def available(self):
        '''Return all of the targets that may be attached to.'''
        result = {name for name in self.__attachable__}
        return sorted(result)

    def list(self):
        '''List all of the available targets with their prototype and description.'''
        klass, sorted = self.__klass__, self.available
        attributes = {item : getattr(klass, item) for item in sorted}
        documentation = {item : autodocumentation.__doc__ for item, autodocumentation in attributes.items()}

        # If there weren't any attributes, then we can just leave.
        if not sorted:
            return six.print_(u"There are no available targets for {:s}.".format(klass.__name__))

        # Define a closure that we can use to extract the parameters from the documentation.
        # FIXME: This should be extracting the actual documentation instead of just the prototype.
        def parameters(doc):
            filtered = filter(None, doc.split('\n'))
            prototype = next(item for item in filtered)
            replaced = prototype.replace('self, ', '').replace('(self)', '()')
            return replaced.strip()

        # Figure out the lengths of each of the columns so that we can align them.
        length = max(map(len, map("{:s}:".format, sorted)))

        # Iterate through all of the sorted items and output them.
        six.print_(u"List of events for {:s}".format(klass.__name__))
        for item in sorted:
            doc = documentation[item]
            six.print_(u"{:<{:d}s} {:s}".format("{:s}:".format(item), length, parameters(doc)))
        return

    def close(self):
        '''Detach from all of the targets that are currently attached and disconnect the instance.'''
        cls = self.__class__
        if not super(priorityhook, self).close():
            logging.critical(u"{:s}.close() : Error trying to detach from all of the targets attached by ({!s}).".format('.'.join([__name__, cls.__name__]), self.object))
            [logging.debug(u"{:s}.close() : Instance ({!r}) is still attached to target {:s}.".format('.'.join([__name__, cls.__name__]), self.object, self.__formatter__(target))) for target in self]

        # Now that everything has been detached, disconnect the instance from all of its events.
        if self.object.unhook():
            return True

        # Log a warning if we were unable to disconnect our instance.
        logging.warning(u"{:s}.close() : Error trying to disconnect the instance ({!r}) from its events.".format('.'.join([__name__, cls.__name__]), self.object))
        return False

    def attach(self, name):
        '''Attach to the target specified by `name`.'''
        cls = self.__class__
        if name not in self.__attachable__:
            raise NameError(u"{:s}.attach({!r}) : Unable to attach to the target ({:s}) due to the target being unavailable.".format('.'.join([__name__, cls.__name__]), name, self.__formatter__(name)))

        # if the attribute is already assigned to our instance, then
        # the target name has already been attached.
        if name in self.__attached__:
            logging.warning(u"{:s}.attach({!r}) : Unable to attach to the target ({:s}) as it has already been attached to.".format('.'.join([__name__, cls.__name__]), name, self.__formatter__(name)))
            return True

        # attach the super class to grab the callable. if successful, then we
        # generate the supermethod for the target in preparation for a closure.
        ok, callable = super(priorityhook, self).attach(name)
        if ok:
            self.__attached__[name] = callable

            # now we can create a new instance of the hook object and update it
            # with the currently attached methods.
            with self.__instance__() as attach:
                attach.update(self.__attached__)

            # log some information and then leave because we were successful.
            logging.info(u"{:s}.attach({!r}) : Attached to the specified target ({:s}).".format('.'.join([__name__, cls.__name__]), name, self.__formatter__(name)))
            return True

        # otherwise we failed, and we need to try to detach from the target using
        # the supermethod in order to remove the target name from the cache.
        if not super(priorityhook, self).detach(name):
            logging.critical(u"{:s}.attach({!r}) : Unable to remove the specified target ({:s}) from the cache of callable items.".format('.'.join([__name__, cls.__name__]), name, self.__formatter__(name)))
            return False

        # we've removed the target name from the cache, so just warn the user
        # that we were unable to attach to the target that was specified.
        logging.warning(u"{:s}.attach({!r}) : Unable to attach to the specified target ({:s}).".format('.'.join([__name__, cls.__name__]), name, self.__formatter__(name)))
        return False

    def detach(self, name):
        '''Detach from the target specified by `name`.'''
        cls = self.__class__
        if name not in self.__attachable__:
            raise NameError(u"{:s}.detach({!r}) : Unable to detach from the target ({:s}) due to the target being unavailable.".format('.'.join([__name__, cls.__name__]), name, self.__formatter__(name)))

        # Check that the target name is currently attached.
        if name not in self.__attached__:
            logging.warning(u"{:s}.detach({!r}) : Unable to detach from the target ({:s}) as it is not currently attached.".format('.'.join([__name__, cls.__name__]), name, self.__formatter__(name)))
            return False

        # When detaching, we need to empty the cache for the provided target
        # before we actually unhook things.
        for callable in self.get(name):
            ok = self.discard(name, callable)
            Flogging = logging.info if ok else logging.warning
            Flogging(u"{:s}.detach({!r}) : {:s} the callable ({!s}) attached to the requested target ({:s}).".format('.'.join([__name__, cls.__name__]), name, 'Discarded' if ok else 'Unable to discard', callable, self.__formatter__(name)))

        # Now we just need to detach the target name from our attachable
        # state, and then apply it to a new instance of the hook object.
        self.__attached__.pop(name)
        with self.__instance__() as attach:
            attach.update(self.__attached__)
        return super(priorityhook, self).detach(name)

    def add(self, name, callable, priority=0):
        '''Add the `callable` to the queue for the specified `name` with the given `priority`.'''

        # If it's already attached, then we can simply add it.
        if name in self:
            return super(priorityhook, self).add(name, callable, priority)

        # Try and attach to the target name with a closure.
        if not self.attach(name):
            cls, format = self.__class__, "{:+d}".format if isinstance(priority, internal.types.integer) else "{!r}".format
            raise internal.exceptions.DisassemblerError(u"{:s}.add({!r}, {!s}, {:s}) : Unable to attach to the specified target ({:s}).".format('.'.join([__name__, cls.__name__]), name, callable, format(priority), self.__formatter__(name)))

        # We should've attached, so all that's left is to add it for
        # tracking using the parent method.
        return super(priorityhook, self).add(name, callable, priority)

    def discard(self, name, callable):
        '''Discard the specified `callable` from hooking the event `name`.'''
        if name not in self.__attachable__:
            cls = self.__class__
            raise NameError(u"{:s}.discard({!r}, {!s}) : Unable to discard the callable ({!s}) from the cache due to the target ({:s}) being unavailable.".format('.'.join([__name__, cls.__name__]), name, callable, callable, self.__formatter__(name)))
        return super(priorityhook, self).discard(name, callable)

    def __repr__(self):
        klass = self.__klass__
        if len(self):
            res, items = "Events currently connected to {:s}:".format(klass.__name__), super(priorityhook, self).__repr__().split('\n')
            return '\n'.join([res] + items[1:])
        return "Events currently connected to {:s}: {:s}".format(klass.__name__, 'No events are connected.')

class prioritynotification(prioritybase):
    """
    Helper class for allowing one to apply an arbitrary number of hooks to the
    different notification points within IDA.
    """
    def __init__(self):
        super(prioritynotification, self).__init__()
        self.__lookup = { getattr(idaapi, name) : name for name in dir(idaapi) if name.startswith('NW_') }

    def __formatter__(self, notification):
        name = self.__lookup.get(notification, '')
        return "{:s}({:#x})".format(name, notification) if name else "{:#x}".format(notification) if isinstance(notification, internal.types.integer) else "{!r} (notification needs to be an integer)".format(notification)

    @property
    def available(self):
        '''Return all of the notifications that may be attached to.'''
        result = {notification for notification in self.__lookup}
        return sorted(result)

    def attach(self, notification):
        '''Attach to the specified `notification` in order to receive events from it.'''
        ok, callable = super(prioritynotification, self).attach(notification)
        return ok and idaapi.notify_when(notification, callable)

    def detach(self, notification):
        '''Detach from the specified `notification` so that events from it will not be received.'''

        # Iterate through all of our callables, and empty the cache since we're
        # actually shutting everything down here.
        cls = self.__class__
        for callable in self.get(notification):
            ok = self.discard(notification, callable)
            Flogging = logging.info if ok else logging.warning
            Flogging(u"{:s}.detach({:#x}) : {:s} the callable ({!s}) attached to the notification {:s}.".format('.'.join([__name__, cls.__name__]), notification, 'Discarded' if ok else 'Unable to discard', callable, self.__formatter__(notification)))

        # Define a dummy closure to pass to the api to avoid a dereference.
        def closure(*parameters):
            return True

        # Now we can actually pass the correct flag to remove the notification.
        ok = idaapi.notify_when(notification | idaapi.NW_REMOVE, closure)
        return ok and super(prioritynotification, self).detach(notification)

    def add(self, notification, callable, priority=0):
        '''Add the `callable` to the queue with the given `priority` for the specified `notification`.'''
        if notification in self:
            return super(prioritynotification, self).add(notification, callable, priority)

        # Notifications are always attached and enabled.
        ok = self.attach(notification)
        if not ok:
            cls = self.__class__
            raise internal.exceptions.DisassemblerError(u"{:s}.add({:#x}, {!s}, {:+d}) : Unable to attach to the notification {:s}.".format('.'.join([__name__, cls.__name__]), notification, callable, priority, self.__formatter__(notification)))

        # Add the callable to our attached notification.
        return super(prioritynotification, self).add(notification, callable, priority)

    def __repr__(self):
        if len(self):
            res, items = 'Notifications currently tracked:', super(prioritynotification, self).__repr__().split('\n')
            return '\n'.join([res] + items[1:])
        return "Notifications currently tracked: {:s}".format('No notifications are being tracked.')

class priorityhxevent(prioritybase):
    """
    Helper class for allowing one to apply an arbitrary number of hooks to the
    different event points within Hex-Rays.
    """
    def __init__(self):
        super(priorityhxevent, self).__init__()
        try:
            import ida_hexrays
        except Exception:
            cls = self.__class__
            raise internal.exceptions.UnsupportedCapability(u"{:s} : Unable to instantiate class due to missing module ({:s}).".format('.'.join([__name__, cls.__name__]), 'ida_hexrays'))
        else:
            self.__module = module = ida_hexrays

        # Initialize the hexrays plugin and make sure we're good to go.
        if not module.init_hexrays_plugin():
            cls = self.__class__
            raise internal.exceptions.DisassemblerError(u"{:s} : Failure while trying initialize the Hex-Rays plugin ({:s}).".format('.'.join([__name__, cls.__name__]), 'init_hexrays_plugin'))

        # Stash our events so that we can pretty-print them and keep a dict
        # that contains the callable that is currently attached to the event.
        self.__events__ = { getattr(ida_hexrays, name) : name for name in dir(ida_hexrays) if name.startswith(('hxe_', 'lxe_')) }
        self.__attached__ = {}

    def __formatter__(self, event):
        name = self.__events__.get(event, '')
        return "{:s}({:#x})".format(name, event) if name else "{:#x}".format(event) if isinstance(event, internal.types.integer) else "{!r} (event needs to be an integer)".format(event)

    @property
    def available(self):
        '''Return all of the events that one may want to attach to.'''
        result = {event for event in self.__events__}
        return sorted(result)

    def attach(self, event):
        '''Attach to the specified `event` in order to receive them from Hex-Rays.'''
        cls = self.__class__
        if event not in self.__events__:
            raise NameError(u"{:s}.attach({!r}) : Unable to attach to the event {:s} due to the event being unavailable.".format('.'.join([__name__, cls.__name__]), event, self.__formatter__(event)))

        # If the event is already there, then the target has been attached
        if event in self.__attached__:
            logging.warning(u"{:s}.attach({!r}) : Unable to attach to the event {:s} as it has already been attached to.".format('.'.join([__name__, cls.__name__]), event, self.__formatter__(event)))
            return True

        # Attach using the super class to figure out what callable we should use.
        ok, callable = super(priorityhxevent, self).attach(event)

        # We failed...nothing to see here.
        if not ok:
            logging.warning(u"{:s}.attach({!r}) : Unable to attach to the event {:s}.".format('.'.join([__name__, cls.__name__]), event, self.__formatter__(event)))
            return False

        # Now we have a callable to use, so we just need to install it.
        if not self.__module.install_hexrays_callback(callable):
            logging.warning(u"{:s}.attach({!r}) : Unable to attach to the event {:s} with the specified callable ({!s}).".format('.'.join([__name__, cls.__name__]), event, self.__formatter__(event), callable))
            return False

        # Last thing to do is to save our state so that we can remove it later.
        self.__attached__[event] = callable
        return True

    def detach(self, event):
        '''Detach from the specified `event` so that they will not be received by Hex-Rays.'''
        cls = self.__class__
        if event not in self.__events__:
            raise NameError(u"{:s}.detach({!r}) : Unable to detach from the event {:s} due to the event being unavailable.".format('.'.join([__name__, cls.__name__]), event, self.__formatter__(event)))

        # If it's not connected, then we need to freak out at the user.
        if event not in self.__attached__:
            logging.warning(u"{:s}.detach({!r}) : Unable to detach from the event {:s} as it is not currently attached.".format('.'.join([__name__, cls.__name__]), event, self.__formatter__(event)))
            return False

        # When detaching, we need to empty the cache for the provided target
        # before we can remove the hexrays callback.
        for callable in self.get(event):
            ok = self.discard(event, callable)
            Flogging = logging.info if ok else logging.warning
            Flogging(u"{:s}.detach({!r}) : {:s} the callable ({!s}) attached to the event {:s}.".format('.'.join([__name__, cls.__name__]), event, 'Discarded' if ok else 'Unable to discard', callable, self.__formatter__(event)))

        # Because Hex-Rays callback API wants the original callable that we gave it,
        # we need to rip it out of our state so we can remove it.
        callable = self.__attached__.pop(event)
        count = self.__module.remove_hexrays_callback(callable)
        logging.info(u"{:s}.detach({!r}) : Removed {:d} callback{:s} for the callable ({!s}) attached to the event {:s}.".format('.'.join([__name__, cls.__name__]), event, count, '' if count == 1 else 's', callable, self.__formatter__(event)))

        return super(priorityhxevent, self).detach(event)

    def close(self):
        '''Remove all of the events that are currently attached.'''
        cls = self.__class__
        if not super(priorityhxevent, self).close():
            logging.critical(u"{:s}.close() : Error trying to detach from all of the events that are attached.".format('.'.join([__name__, cls.__name__])))
            [logging.debug(u"{:s}.close() : Event {:s} is still attached{:s}.".format('.'.join([__name__, cls.__name__]), self.__formatter__(event), " by callable {!s}".format(self.__attached__[event]) if event in self.__attached__ else '')) for event in self]

        # We only fail here if our state is not empty.
        return False if self.__attached__ else True

    def add(self, event, callable, priority=0):
        '''Add the `callable` to the queue with the given `priority` for the specified `event`.'''
        if event in self:
            return super(priorityhxevent, self).add(event, callable, priority)

        # Attach to the event so that we can actually do stupid things with it.
        if not self.attach(event):
            cls = self.__class__
            raise internal.exceptions.DisassemblerError(u"{:s}.add({:#x}, {!s}, {:+d}) : Unable to attach to the event {:s}.".format('.'.join([__name__, cls.__name__]), event, callable, priority, self.__formatter__(event)))

        # Add the callable to our current events to call.
        return super(priorityhxevent, self).add(event, callable, priority)

    def __apply__(self, event):
        '''Return a closure that will execute all of the callables for the specified `event`.'''
        original = super(priorityhxevent, self).__apply__(event)

        # We need to define this closure because Hex-Rays absolutely requires
        # you to return a 0 unless the event type specifies otherwise.
        def closure(ev, *parameters):
            if ev == event:
                return original(*parameters) or 0
            return 0
        return closure

    def __repr__(self):
        if len(self):
            res, items = 'Events currently attached:', super(priorityhxevent, self).__repr__().split('\n')
            return '\n'.join([res] + items[1:])
        return "Events currently attached: {:s}".format('No events are currently attached to.')

class address(object):
    """
    This namespace provides tools that assist with correcting
    arguments that a user will provide to a function. This includes
    things such as verifying that an argument references an address
    within the database, is pointing to the "head" or "tail" of an
    address, etc.

    This is needed because some APIs that IDAPython exposes tend to
    be crashy when you give it a bogus address. This way parameters
    can be corrected before they're passed to an API that may crash
    IDA.
    """
    @classmethod
    def pframe(cls):
        '''Return the python frame that was called from the main thread.'''
        res = fr = sys._getframe()
        while fr.f_back and fr.f_code.co_name != '<module>':
            res = fr
            fr = fr.f_back
        return res

    @classmethod
    def size(cls, ea):
        '''Return the size of the item at the address `ea`.'''
        return idaapi.get_item_size(ea)

    @internal.utils.multicase(ea=internal.types.integer)
    @classmethod
    def element(cls, ea):
        '''Return the size of the type belonging to the item at the address `ea`.'''
        get_data_elsize = idaapi.get_full_data_elsize if hasattr(idaapi, 'get_full_data_elsize') else idaapi.get_data_elsize
        return get_data_elsize(ea, cls.flags(ea))
    @internal.utils.multicase(ea=internal.types.integer, flags=internal.types.integer)
    @classmethod
    def element(cls, ea, flags):
        '''Return the size of the type belonging to the item at the address `ea` with the given `flags`.'''
        get_data_elsize = idaapi.get_full_data_elsize if hasattr(idaapi, 'get_full_data_elsize') else idaapi.get_data_elsize
        return get_data_elsize(ea, flags)
    @internal.utils.multicase(flags=internal.types.integer, info=(idaapi.opinfo_t, internal.types.none))
    @classmethod
    def element(cls, flags, info):
        '''Return the size of the type with the given `flags` and operand information in `info`.'''
        get_data_elsize = idaapi.get_full_data_elsize if hasattr(idaapi, 'get_full_data_elsize') else idaapi.get_data_elsize
        return get_data_elsize(idaapi.BADADDR, flags) if info is None else get_data_elsize(idaapi.BADADDR, flags, info)

    @internal.utils.multicase(ea=internal.types.integer)
    @classmethod
    def flags(cls, ea):
        '''Return the flags of the item at the address `ea`.'''
        getflagsex = idaapi.get_flags_ex if hasattr(idaapi, 'get_flags_ex') else (lambda ea, _: idaapi.get_full_flags(ea)) if hasattr(idaapi, 'get_full_flags') else (lambda ea, _: idaapi.getFlags(ea))
        return idaapi.as_uint32(getflagsex(ea, getattr(idaapi, 'GFE_VALUE', 0)))
    @internal.utils.multicase(ea=internal.types.integer, mask=internal.types.integer)
    @classmethod
    def flags(cls, ea, mask):
        '''Return the flags at the address `ea` masked with `mask`.'''
        getflagsex = idaapi.get_flags_ex if hasattr(idaapi, 'get_flags_ex') else (lambda ea, _: idaapi.get_full_flags(ea)) if hasattr(idaapi, 'get_full_flags') else (lambda ea, _: idaapi.getFlags(ea))
        return getflagsex(ea, getattr(idaapi, 'GFE_VALUE', 0)) & idaapi.as_uint32(mask)
    @internal.utils.multicase(ea=internal.types.integer, mask=internal.types.integer, value=internal.types.integer)
    @classmethod
    def flags(cls, ea, mask, value):
        '''Sets the flags at the address `ea` masked with `mask` to the specified `value`.'''
        getflagsex = idaapi.get_flags_ex if hasattr(idaapi, 'get_flags_ex') else (lambda ea, _: idaapi.get_full_flags(ea)) if hasattr(idaapi, 'get_full_flags') else (lambda ea, _: idaapi.getFlags(ea))
        if hasattr(idaapi, 'setFlags'):
            res = getflagsex(ea, getattr(idaapi, 'GFE_VALUE', 0))
            idaapi.setFlags(ea, (res & ~mask) | value)
            return res & mask
        raise internal.exceptions.UnsupportedVersion(u"{:s}.flags({:#x}, {:#x}, {:d}) : IDA has deprecated the ability to modify the flags for an address.".format('.'.join([__name__, cls.__name__]), ea, mask, value))

    @classmethod
    def references(cls, ea):
        '''Return each address within the item at address `ea` that has a reference to it.'''
        getflagsex = idaapi.get_flags_ex if hasattr(idaapi, 'get_flags_ex') else (lambda ea, _: idaapi.get_full_flags(ea)) if hasattr(idaapi, 'get_full_flags') else (lambda ea, _: idaapi.getFlags(ea))
        return [ea for ea in builtins.range(ea, ea + idaapi.get_item_size(ea)) if getflagsex(ea, 0) & idaapi.FF_REF]

    @classmethod
    def bounds(cls):
        '''Return the smallest and largest address within the database as a tuple.'''
        if idaapi.__version__ < 7.2:
            info = idaapi.get_inf_structure()
            min, max = info.minEA, info.maxEA
        else:
            min, max = idaapi.inf_get_min_ea(), idaapi.inf_get_max_ea()
        return min, max

    @classmethod
    def __within__(cls, ea):
        l, r = cls.bounds()
        return l <= ea < r

    @classmethod
    def __head1__(cls, ea, **warn):
        '''Adjusts `ea` so that it is pointing to the beginning of an item.'''
        entryframe = cls.pframe()
        logF = logging.warning if warn.get('warn', False) else logging.debug

        res = idaapi.get_item_head(ea)
        if ea != res:
            logF(u"{:s}({:#x}) : Specified address {:#x} is not pointing to the beginning of an item. Setting the address to {:#x}.".format(entryframe.f_code.co_name, ea, ea, res))
        return res
    @classmethod
    def __head2__(cls, start, end, **warn):
        '''Adjusts both `start` and `end` so that each are pointing to the beginning of their respective items.'''
        entryframe = cls.pframe()
        logF = logging.warning if warn.get('warn', False) else logging.debug

        res_start, res_end = sorted([start, end])
        if idaapi.get_item_head(res_start) == idaapi.get_item_head(res_end):
            left, right = idaapi.get_item_head(res_start), idaapi.get_item_end(res_end)
        else:
            left, right = idaapi.get_item_head(res_start), res_end if idaapi.get_item_head(res_end) == res_end else idaapi.get_item_end(res_end)

        # FIXME: off-by-one here, as end can be the size of the db.
        if res_start != start:
            logF(u"{:s}({:#x}, {:#x}) : Starting address of {:#x} is not pointing to the beginning of an item. Setting the address to {:#x}.".format(entryframe.f_code.co_name, start, end, res_start, left))
        if res_end != end:
            logF(u"{:s}({:#x}, {:#x}) : Ending address of {:#x} is not pointing to the beginning of an item. Setting the address to {:#x}.".format(entryframe.f_code.co_name, start, end, res_end, right))
        return left, right
    @classmethod
    def head(cls, *args, **warn):
        '''Adjusts the specified addresses so that they point to the beginning of their specified items.'''
        if len(args) > 1:
            return cls.__head2__(*args, **warn)
        return cls.__head1__(*args, **warn)

    @classmethod
    def __tail1__(cls, ea, **warn):
        '''Adjusts `ea` so that it is pointing to the end of an item.'''
        entryframe = cls.pframe()
        logF = logging.warning if warn.get('warn', False) else logging.debug

        res = idaapi.get_item_end(ea)
        if ea != res:
            logF(u"{:s}({:#x}) : Specified address {:#x} not pointing to the end of an item. Setting the address to {:#x}.".format(entryframe.f_code.co_name, ea, ea, res))
        return res
    @classmethod
    def __tail2__(cls, start, end, **warn):
        '''Adjusts both `start` and `end` so that each are pointing to the end of their respective items.'''
        entryframe = cls.pframe()
        logF = logging.warning if warn.get('warn', False) else logging.debug

        res_start, res_end = idaapi.get_item_end(start), idaapi.get_item_end(end)
        # FIXME: off-by-one here, as end can be the size of the db.
        if res_start != start:
            logF(u"{:s}({:#x}, {:#x}) : Starting address of {:#x} is not pointing to the end of an item. Setting the address to {:#x}.".format(entryframe.f_code.co_name, start, end, start, res_start))
        if res_end != end:
            logF(u"{:s}({:#x}, {:#x}) : Ending address of {:#x} is not pointing to the end of an item. Setting the address to {:#x}.".format(entryframe.f_code.co_name, start, end, end, res_end))
        return res_start, res_end
    @classmethod
    def tail(cls, *args, **warn):
        '''Adjusts the specified addresses so that they point to the end of their specified items.'''
        if len(args) > 1:
            return cls.__tail2__(*args, **warn)
        return cls.__tail1__(*args, **warn)

    @classmethod
    def __inside1__(cls, ea):
        '''Check that `ea` is within the database and adjust it to point to the beginning of its item.'''
        entryframe = cls.pframe()

        if not isinstance(ea, internal.types.integer):
            raise internal.exceptions.InvalidParameterError(u"{:s}({:#x}) : The specified address {!r} is not an integral type ({!r}).".format(entryframe.f_code.co_name, ea, ea, ea.__class__))

        if ea == idaapi.BADADDR:
            raise internal.exceptions.InvalidParameterError(u"{:s}({:#x}) : An invalid address ({:#x}) was specified.".format(entryframe.f_code.co_name, ea, ea))

        res = cls.within(ea)
        return cls.head(res, warn=False)
    @classmethod
    def __inside2__(cls, start, end):
        '''Check that both `start` and `end` are within the database and adjust them to point at their specified range.'''

        entryframe = cls.pframe()
        start, end = cls.within(start, end)
        if not isinstance(start, internal.types.integer) or not isinstance(end, internal.types.integer):
            raise internal.exceptions.InvalidParameterError(u"{:s}({:#x}, {:#x}) : The specified addresses ({!r}, {!r}) are not integral types ({!r}, {!r}).".format(entryframe.f_code.co_name, start, end, start, end, start.__class__, end.__class__))

        left, right = sorted([start, end])
        if idaapi.get_item_head(left) == idaapi.get_item_head(right):
            return idaapi.get_item_head(start), idaapi.get_item_end(end) - 1
        return idaapi.get_item_head(start), idaapi.get_item_head(end) - 1
    @classmethod
    def inside(cls, *args):
        '''Check the specified addresses are within the database and adjust so that they point to their item or range.'''
        if len(args) > 1:
            return cls.__inside2__(*args)
        return cls.__inside1__(*args)

    @classmethod
    def __within1__(cls, ea):
        '''Check that `ea` is within the database.'''
        entryframe = cls.pframe()

        if not isinstance(ea, internal.types.integer):
            raise internal.exceptions.InvalidParameterError(u"{:s}({:#x}) : The specified address {!r} is not an integral type ({!r}).".format(entryframe.f_code.co_name, ea, ea, ea.__class__))

        if ea == idaapi.BADADDR:
            raise internal.exceptions.InvalidParameterError(u"{:s}({:#x}) : An invalid address {:#x} was specified.".format(entryframe.f_code.co_name, ea, ea))

        if not cls.__within__(ea):
            l, r = cls.bounds()
            raise internal.exceptions.OutOfBoundsError(u"{:s}({:#x}) : The specified address {:#x} is not within the bounds of the database ({:#x}<>{:#x}).".format(entryframe.f_code.co_name, ea, ea, l, r))
        return ea
    @classmethod
    def __within2__(cls, start, end):
        '''Check that both `start` and `end` are within the database.'''
        entryframe = cls.pframe()

        if not isinstance(start, internal.types.integer) or not isinstance(end, internal.types.integer):
            raise internal.exceptions.InvalidParameterError(u"{:s} : The specified addresses ({!r}, {!r}) are not integral types ({!r}, {!r}).".format(entryframe.f_code.co_name, start, end, start.__class__, end.__class__))

        # If the start and end are matching, then we don't need to fit the bounds.
        if any(not cls.__within__(ea) for ea in [start, end if start == end else end - 1]):
            l, r = cls.bounds()
            raise internal.exceptions.OutOfBoundsError(u"{:s}({:#x}, {:#x}) : The specified range ({:#x}<>{:#x}) is not within the bounds of the database ({:#x}<>{:#x}).".format(entryframe.f_code.co_name, start, end, start, end, l, r))
        return start, end
    @classmethod
    def within(cls, *args):
        '''Check that the specified addresses are within the database.'''
        if len(args) > 1:
            return cls.__within2__(*args)
        return cls.__within1__(*args)

    @internal.utils.multicase(ea=internal.types.integer)
    @classmethod
    def refinfo(cls, ea):
        '''This returns the ``idaapi.refinfo_t`` for the address given in `ea`.'''
        OPND_ALL = getattr(idaapi, 'OPND_ALL', 0xf)
        return cls.refinfo(ea, OPND_ALL)
    @internal.utils.multicase(ea=internal.types.integer, opnum=internal.types.integer)
    @classmethod
    def refinfo(cls, ea, opnum):
        '''This returns the ``idaapi.refinfo_t`` for the operand `opnum` belonging to the address given in `ea`.'''
        ri = idaapi.refinfo_t()
        ok = idaapi.get_refinfo(ea, opnum, ri) if idaapi.__version__ < 7.0 else idaapi.get_refinfo(ri, ea, opnum)
        return ri if ok else None

    @classmethod
    def update_refinfo(cls, ea, flag):
        '''This updates the refinfo for the identifer given by `ea` according to the provided `flag`.'''
        get_refinfo = (lambda ri, ea, opnum: idaapi.get_refinfo(ea, opnum, ri)) if idaapi.__version__ < 7.0 else idaapi.get_refinfo
        set_refinfo, opmasks = idaapi.set_refinfo, [idaapi.FF_0OFF, idaapi.FF_1OFF]

        # Refinfo seems to be relevant to a given operand, but users really only
        # apply types to addresse unless it's an explicit operand type. So, what
        # we'll do to deal with this is take the flag that we're given and use
        # it to figure out which actual operand is being updated so that we don't
        # have to assume the one that IDA uses based on whatever's being updated.
        dtype, dsize = flag & typemap.FF_MASK, flag & typemap.FF_MASKSIZE

        # First we'll grab the size and make sure that we actually support it.
        # We should.. because we support all of IDA's native types. Then we
        # generate a list of all of the available operands to apply the ref to.
        if dsize in typemap.inverted:
            ptype, (_, size) = type, typemap.inverted[dsize]
            ritype = ptype, size
            ptrmask, _ = typemap.ptrmap[ritype]
            operands = [index for index, opmask in enumerate(opmasks) if dtype & ptrmask & opmask]

        # Anything else means that there's no references to update. If the flags say
        # that it is a string, then we already know that there's nothing to update.
        else:
            FF_STRLIT = idaapi.FF_STRLIT if hasattr(idaapi, 'FF_STRLIT') else idaapi.FF_ASCI
            if dsize != FF_STRLIT:
                logging.warning(u"{:s}.update_refinfo({:#x}, {:#x}) : Unable to determine the default reference type size due to the type ({:#0{:d}x}) from the flags ({:#0{:d}x}) being unsupported..".format('.'.join([__name__, cls.__name__]), ea, flag, dsize, 2 + 8, flag, 2 + 8))
            return 0

        # Before we change anything, do a smoke-test to ensure that we actually
        # are able to choose a default reference size if we're going to update.
        if len(operands) > 0 and ritype not in typemap.refinfomap:
            logging.warning(u"{:s}.update_refinfo({:#x}, {:#x}) : Unable to determine a default reference type for the given size ({:d}).".format('.'.join([__name__, cls.__name__]), ea, flag, size))
            return 0

        # Now we can choose our type from the refinfomap, and apply it to each
        # operand in our list of operands that we just resolved. The set_refinfo
        # api should _never_ fail, so we only log warnings if they do.
        api = [set_refinfo.__module__, set_refinfo.__name__] if hasattr(set_refinfo, '__module__') else [set_refinfo.__name__]
        for opnum in operands:
            if not set_refinfo(ea, opnum, typemap.refinfomap[ritype]):
                logging.warning(u"{:s}.update_refinfo({:#x}, {:#x}) : The api call to `{:s}(ea={:#x}, n={:d}, ri={:d})` returned failure.".format('.'.join([__name__, cls.__name__]), ea, flag, '.'.join(api), ea, opnum, typemap.refinfomap[ritype]))
            continue

        # FIXME: figure out how to update the ui so that it references the new
        #        information but without any dumb performance issues (that might
        #        be caused by asking it to redraw everything).

        # Just return the total number of operands that we updated...for now.
        return len(operands)

class range(object):
    """
    This namespace provides tools that assist with interacting with IDA 6.x's
    ``idaapi.area_t``, or IDA 7.x's ``idaapi.range_t`` in a generic manner
    without needing to know which version of IDA is being used or if the IDA
    6.95 compatibility layer is enabled.
    """

    # Define some classmethods for accessing area_t attributes in versions of IDA
    # prior to IDA 7.0.
    @classmethod
    def start_6x(cls, area):
        '''Return the "startEA" attribute of the specified `area`.'''
        return area.startEA
    @classmethod
    def end_6x(cls, area):
        '''Return the "endEA" attribute of the specified `area`.'''
        return area.endEA

    # Now we can do it for versions of IDA 7.0 and newer..
    @classmethod
    def start_7x(cls, area):
        '''Return the "startEA" attribute of the specified `area`.'''
        return area.start_ea
    @classmethod
    def end_7x(cls, area):
        '''Return the "end_ea" attribute of the specified `area`.'''
        return area.end_ea

    # Assign them based on the IDA version and add some aliases for it.
    start, end = (start_6x, end_6x) if idaapi.__version__ < 7.0 else (start_7x, end_7x)
    left, right, stop = start, end, end
    del(start_6x)
    del(end_6x)
    del(start_7x)
    del(end_7x)

    @classmethod
    def unpack(cls, area):
        '''Unpack the boundaries of the specified `area` as a tuple.'''
        return cls.start(area), cls.end(area)

    @classmethod
    def pack(cls, start, stop):
        '''Pack the address at `start` up to `stop` (exclusive) into a `range_t`.'''
        return idaapi.area_t(start, stop) if idaapi.__version__ < 7.0 else idaapi.range_t(start, stop)

    @classmethod
    def bounds(cls, area):
        '''Return the boundaries of the specified `area` as a ``bounds_t``.'''
        left, right = cls.unpack(area)
        return bounds_t(left, right) if left == right else bounds_t(left, right)

    @classmethod
    def within(cls, ea, area):
        '''Return whether the address `ea` is contained by the specified `area`.'''
        left, right = cls.unpack(area)

        # In IDA, a range_t consistently has a start address that begins
        # before the ending address. This means that if the ending address
        # is less the starting one, that the boundary between them wraps
        # across the highest address.
        if left <= right:
            return left <= ea < right
        return left <= ea or ea < right
    contains = internal.utils.alias(within, 'range')

    @classmethod
    def size(cls, area):
        '''Return the size of the specified `area` by returning the difference of its boundaries.'''
        left, right = cls.unpack(area)
        return right - left

class node(object):
    """
    This namespace contains a number of methods that extract information
    from some of the undocumented structures that IDA stores within
    netnodes for various addresses in a database.

    XXX: Hopefully these are correct!
    """
    @staticmethod
    def identifier(identifier):
        '''Return whether the provided `identifier` is actually valid or not.'''

        # First use the latest official api to get the private range of identifiers.
        if hasattr(idaapi, 'inf_get_privrange'):
            res = idaapi.inf_get_privrange()
            return range.within(identifier, res)

        # Otherwise, ping the module for the next best thing.
        elif all(hasattr(idaapi, item) for item in ['inf_get_privrange_start_ea', 'inf_get_privrange_end_ea']):
            start, stop = idaapi.inf_get_privrange_start_ea(), idaapi.inf_get_privrange_end_ea()
            if start <= stop:
                return start <= identifier < stop
            return start <= identifier or identifier < stop

        # If we couldn't find a privrange for the version of IDA that we care about,
        # then we try and call into IDA's supporting library directly.
        try:
            import ida
            if not hasattr(ida, 'getinf'):
                raise ImportError

        # Every single possible way has failed, so we fall back to calling each and
        # every available api to see if any one of them succeeds.
        except ImportError:
            parameters = 2 * [identifier]
            if any(Fapi(id) for Fapi, id in zip([idaapi.get_struc, idaapi.get_member_by_id], parameters)):
                return True
            iterable = (Fapi(id) for Fapi, id in zip([idaapi.get_enum_idx, idaapi.get_enum_member_enum], parameters))
            return not all(map(functools.partial(operator.eq, idaapi.BADADDR), iterable))

        # Otherwise we need to grab the INF index for both boundaries.
        INF_PRIVRANGE_START_EA = getattr(idaapi, 'INF_PRIVRANGE_START_EA', 27)
        INF_PRIVRANGE_END_EA = getattr(idaapi, 'INF_PRIVRANGE_END_EA', 28)

        # Then we can query for them with IDC's getinf() before testing them.
        bounds = map(ida.getinf, [INF_PRIVRANGE_START_EA, INF_PRIVRANGE_END_EA])
        start, stop = map(functools.partial(operator.and_, idaapi.BADADDR), bounds)
        if start <= stop:
            return start <= identifier < stop
        return start <= identifier or identifier < stop
    is_identifier = internal.utils.alias(identifier, 'node')

    @internal.utils.multicase(sup=internal.types.bytes)
    @classmethod
    def sup_functype(cls, sup, *supfields):
        """Given a supval, return the pointer size, model, calling convention, return type, and a tuple composed of the argument stack size and the arguments for a function.

        These bytes are typically found in a supval[0x3000] of a function.
        """
        res, ti = [], idaapi.tinfo_t()
        if not ti.deserialize(None, sup, *itertools.chain(supfields, [None] * (2 - min(2, len(supfields))))):
            raise internal.exceptions.DisassemblerError(u"{:s}.sup_functype(\"{!s}\") : Unable to deserialize the type information that was received.".format('.'.join([__name__, node.__name__]), internal.utils.string.tohex(sup)))

        # Fetch the pointer size and the model from the realtype byte.
        if not ti.is_func():
            raise internal.exceptions.InvalidTypeOrValueError(u"{:s}.sup_functype(\"{!s}\") : The type that was received ({!s}) was not a function type.".format('.'.join([__name__, node.__name__]), internal.utils.string.tohex(sup), ti))
        byte = ti.get_realtype()
        ptrsize, model = byte & idaapi.CM_MASK, byte & idaapi.CM_M_MASK
        res += [ptrsize, model]

        # Now we can get the calling convention and append the return type.
        ftd = idaapi.func_type_data_t()
        if not ti.get_func_details(ftd):
            raise internal.exceptions.MissingTypeOrAttribute(u"{:s}.sup_functype(\"{!s}\") : Unable to get the function's details from the received type information.".format('.'.join([__name__, node.__name__]), internal.utils.string.tohex(sup)))
        byte = ftd.cc
        cc, spoiled_count = byte & idaapi.CM_CC_MASK, byte & ~idaapi.CM_CC_MASK
        res += [cc, ftd.rettype]

        # If the argument locations have been calculated, then we can add
        # them to our results. For sanity, we first validate that the number
        # of arguments corresponds to the number of elements in our ftd array.
        if ftd.flags & idaapi.FTI_ARGLOCS:
            number = ti.get_nargs()
            if number != len(ftd):
                raise internal.exceptions.AssertionError(u"{:s}.sup_functype(\"{!s}\") : The number of arguments for the function type ({:d}) does not match the number of arguments that were returned ({:d}).".format('.'.join([__name__, node.__name__]), internal.utils.string.tohex(sup), number, len(ftd)))

            # To grab the arguments, we need to figure out the count because our arguments
            # will be a tuple composed of the (name, type, comment) for each one.
            arguments = []
            for index in builtins.range(ti.get_nargs()):
                item = ftd[index]
                typename, typeinfo, typecomment = item.name, item.type, item.cmt
                arguments.append(typeinfo if not len(supfields) else (typeinfo, typename) if len(supfields) == 1 else (typeinfo, typename, typecomment))

            # Include the size for the arguments on the stack along with the
            # arguments that we just extracted.argument size along with the arguments.
            arglocs = ftd.stkargs, arguments

        # If the argument locations weren't calculated, then the next element we
        # append is the size of the stack that is allocated to the arguments.
        else:
            arglocs = ftd.stkargs
        res += [arglocs]

        # Now we can return everything that we've collected from the type.
        return tuple(res)
    @internal.utils.multicase(sup=internal.types.bytes, ptrsize=(internal.types.none, internal.types.integer), model=(internal.types.none, internal.types.integer), cc=(internal.types.none, internal.types.integer), rettype=(internal.types.none, idaapi.tinfo_t), arglocs=(internal.types.none, internal.types.ordered))
    @classmethod
    def sup_functype(cls, sup, ptrsize, model, cc, rettype, arglocs):
        '''Given the old supval, re-encode any of the given parameters into it whilst ignoring the parameters that are specified as ``None``.'''

        # First decode the type information that we were given since we're going
        # to use it to reconstruct the supval.
        res, ti = bytearray(), idaapi.tinfo_t()
        if not ti.deserialize(None, sup, None):
            raise internal.exceptions.DisassemblerError(u"{:s}.sup_functype(\"{!s}\", ...) : Unable to deserialize the type information that was received.".format('.'.join([__name__, node.__name__]), internal.utils.string.tohex(sup)))

        # If it's not a function, then refuse to process it.
        if not ti.is_func():
            raise internal.exceptions.InvalidTypeOrValueError(u"{:s}.sup_functype(\"{!s}\", ...) : The type that was received ({!s}) was not a function type.".format('.'.join([__name__, node.__name__]), internal.utils.string.tohex(sup), ti))

        # Grab the extra function details so that we can sort out the caling
        # convention and types.
        ftd = idaapi.func_type_data_t()
        if not ti.get_func_details(ftd):
            raise internal.exceptions.MissingTypeOrAttribute(u"{:s}.sup_functype(\"{!s}\", ...) : Unable to get the function's details from the received type information.".format('.'.join([__name__, node.__name__]), internal.utils.string.tohex(sup)))

        # Verify that our arglocs were calculated and the number matches our type.
        if ftd.flags & idaapi.FTI_ARGLOCS:
            number = ti.get_nargs()
            if number != len(ftd):
                raise internal.exceptions.AssertionError(u"{:s}.sup_functype(\"{!s}\", ...) : The number of arguments for the function type ({:d}) does not match the number of arguments that were returned ({:d}).".format('.'.join([__name__, node.__name__]), internal.utils.string.tohex(sup), number, len(ftd)))

        # Start out by grabbing the first byte and compose it from the ptrsize and model.
        obyte = ti.get_realtype()
        nptrsize = obyte & idaapi.CM_MASK if ptrsize is None else ptrsize & idaapi.CM_MASK
        nmodel = obyte & idaapi.CM_M_MASK if model is None else model & idaapi.CM_M_MASK
        res.append(nptrsize | nmodel)

        # Next we compose the calling convention. We need to extract the count
        # from the old byte since the user should be giving us a straight-up
        # calling convention to use.
        obyte = ftd.cc
        ncc = obyte & idaapi.CM_CC_MASK if cc is None else cc & idaapi.CM_CC_MASK
        nspoiled_count = obyte & ~idaapi.CM_CC_MASK
        res.append(ncc | nspoiled_count)

        # Next in our queue is the serialized return type.
        otype = ftd.rettype
        nbytes, _, _ = otype.serialize() if rettype is None else rettype.serialize()
        res.extend(bytearray(nbytes))

        # The last thing we need to do is to figure out our arguments. First we'll
        # check if the user gave us any. If not, then we'll just use the previously
        # used arguments from the idaapi.tinfo_t. We start with the old length,
        # and then we serialize everything into our result.
        if arglocs is None:
            ocount = len(ftd)
            res.append(1 + ocount)

            # Now we can iterate through all of them and serialize each one
            # so that we can extend our result with it.
            for index in builtins.range(ocount):
                funcarg = ftd[index]
                obytes, _, _ = funcarg.type.serialize()
                res.extend(bytearray(obytes))

            # That was it, so we can append our null-byte because we're done.
            res.append(0)

        # Otherwise the user gave us some new arguments to use which we'll need
        # to serialize in order to extend our result. First we'll need to check
        # if we were given a tuple, because if we were then this is a tuple
        # composed of the argument stack size and our actual argument list.
        else:
            _, arglocs = arglocs if isinstance(arglocs, internal.types.tuple) else (0, arglocs)

            # Now that we have our real list of arguments, we can start by
            # appending the number of arguments that we were given.
            ncount = len(arglocs)
            res.append(1 + ncount)

            # Next we iterate through each of them in order to serialize each
            # one so that we can extend our result with it.
            for index, argloc in builtins.enumerate(arglocs):
                nbytes, _, _ = argloc.serialize()
                res.extend(bytearray(nbytes))

            # Last thing to do is append our null byte.
            res.append(0)

        # We're returning a supval here, so we need to convert our bytearray
        # back to bytes in order for it to be usable.
        return builtins.bytes(res)

    # As the get_stroff_path function doesn't return a full path at all,
    # we need to figure the path ourselves using it as a suggestion.
    @classmethod
    def calculate_stroff_path(cls, offset, suggestion):
        '''Given the provided `offset` and list of identifiers as a `suggestion`, return the delta along with the full structure path as a list of ``idaapi.struc_t``and ``idaapi.member_t` pairs.'''
        items = suggestion[:]

        # After we get the list of member ids, then we can use it to
        # compose the path that we will match against later. We grab
        # the first member (which is the structure id) and convert it
        # to a structure we that we have some place to start.
        st = internal.structure.new(items.pop(0), 0)
        members = [idaapi.get_member_by_id(item) for item in items]
        items = [(sptr if cls.identifier(sptr.id) else idaapi.get_member_struc(idaapi.get_member_fullname(mptr.id)), mptr) for mptr, _, sptr in members]

        # Now we have a list of members, we format it into a dictionary
        # so that we can look up the correct member for any given structure.
        choices = {}
        for sptr, mptr in items:
            choices.setdefault(sptr.id, []).append(mptr)

        # Now we can use the members we received to generate a closure
        # that we'll use to figure out the correct members for the operand.
        def Ffilter(parent, candidates, choices=choices):

            # If the parent is not in our list of choices, then we leave
            # because there's nothing we can do with this.
            if parent.id not in choices:
                return []

            # Grab the list for the current parent and check to see if
            # there's a member in our list that we can use. If so, then
            # we can just return it as the only choice.
            items = choices[parent.id]
            if len(items):
                return [items.pop(0)]

            # If there wasn't anything found, then just return all our
            # candidates because we're not sure how to proceed here.
            return []

        # Now we can fetch the delta and path for the requested offset,
        # and then convert it into a list of sptrs and mptrs in order
        # to return it to the caller.
        path, delta = st.members.__walk_to_realoffset__(offset, filter=Ffilter)

        # That was it, so we just need to convert the path into a list
        # of sptrs and mptrs to return to the caller.
        return delta, [(item.parent.ptr, item.ptr) for item in path]

    @classmethod
    def get_stroff_path(cls, ea, opnum):
        '''Given an address at `ea` and the operand number, return a tuple of the delta and a list of the encoded structure/field identifiers.'''

        # If there's no get_stroff_path, then call the old implementation that decodes
        # the path from the supval of the related netnode.
        if not hasattr(idaapi, 'get_stroff_path'):
            Fnetnode = getattr(idaapi, 'ea2node', internal.utils.fidentity)
            bits = math.trunc(math.ceil(math.log(idaapi.BADADDR, 2)))
            if not internal.netnode.sup.has(Fnetnode(ea), 0xf + opnum):
                return 0, []
            sup = internal.netnode.sup.get(Fnetnode(ea), 0xf + opnum, type=memoryview)
            return cls.sup_opstruct(sup.tobytes(), bits > 32)

        # First grab the instruction, and then use it to get the op_t.
        insn = instruction.at(ea)
        op = instruction.operand(insn.ea, opnum)

        # As IDAPython's get_stroff_path() api doesn't tell us how much
        # space we need to allocate, we need to allocate the maximum first.
        # Only then will we know the count to actually use.
        delta, path = idaapi.sval_pointer(), idaapi.tid_array(idaapi.MAXSTRUCPATH)
        count = idaapi.get_stroff_path(insn.ea, opnum, path.cast(), delta.cast()) if idaapi.__version__ < 7.0 else idaapi.get_stroff_path(path.cast(), delta.cast(), insn.ea, opnum)
        if not count:
            return delta.value(), []

        # Now that we have the right length, we can use IDAPython to
        # actually populate the tid_array here. Afterwards, we discard
        # our array by converting it into a list.
        delta, path = idaapi.sval_pointer(), idaapi.tid_array(count)
        res = idaapi.get_stroff_path(insn.ea, opnum, path.cast(), delta.cast()) if idaapi.__version__ < 7.0 else idaapi.get_stroff_path(path.cast(), delta.cast(), insn.ea, opnum)
        if res != count:
            raise internal.exceptions.DisassemblerError(u"{:s}.get_stroff_path({:#x}, {:d}) : The length ({:d}) for the path at operand {:d} changed ({:d}) during calculation.".format('.'.join([__name__, cls.__name__]), insn.ea, opnum, count, opnum, res))
        return delta.value(), [path[idx] for idx in builtins.range(count)]

    @staticmethod
    def sup_opstruct(sup, bit64Q):
        """DEPRECATED: Given a supval, return a tuple of the delta and a list of the encoded structure/field ids.

        This string is typically found in a supval[0xF + opnum] of the instruction.
        """
        le = functools.partial(functools.reduce, lambda agg, by: (agg * 0x100) | by)
        Fidentifier = getattr(idaapi, 'node2ea', internal.utils.fidentity)

        # jspelman. he's everywhere.
        ror = lambda n, shift, bits: (n>>shift) | ((n & pow(2, shift) - 1) << (bits - shift))

        # 16-bit
        # 0001 9ac1 -- _SYSTEMTIME

        # 32-bit
        # 0001 50
        # 0002 5051
        # 0001 c0006e92 -- ULARGE_INTEGER
        # 0002 c0006e92 c0006e98 -- ULARGE_INTEGER.quadpart
        # 0002 c0006e92 c0006e97 -- ULARGE_INTEGER.u.lowpart
        # 0002 c0006e92 c0006e96 -- ULARGE_INTEGER.s0.lowpart
        # (x ^ 0x3f000000)

        def id32(sup):
            iterable = (item for item in bytearray(sup))

            # First consume the offset (FIXME: we only support 2 bytes for now...)
            by = builtins.next(iterable)
            if le([by]) & 0x80:
                offset = le([by] + [builtins.next(iterable)])
                offset ^= 0x8000
            else:
                offset = 0

            count, rest = le([builtins.next(iterable)]), [item for item in iterable]
            itemsize = (len(rest) // count) if count else 1

            iterable = (item for item in rest)
            chunks = [item for item in zip(*(itemsize * [iterable]))]

            if itemsize == 1:
                return offset, [0xff000000 | le(item) for item in chunks]

            elif itemsize == 2:
                return offset, [0xff000000 | 0x8000 ^ le(item) for item in chunks]

            elif itemsize == 4:
                #res = map(le, chunks)
                #res = map(functools.partial(operator.xor, 0x3f000000), res)
                return offset, [0x3f000000 ^ le(item) for item in chunks]

            raise internal.exceptions.SizeMismatchError(u"{:s}.sup_opstruct(\"{:s}\") -> id32 : An unsupported itemsize ({:d}) was discovered while trying to decode {:d} chunks at offset {:#x} from value ({:s}).".format('.'.join([__name__, node.__name__]), internal.utils.string.tohex(sup), itemsize, count, offset, ["{:0{:d}x".format(item, 2 * itemsize) for item in chunks]))

        # 64-bit
        # 000002 c000888e00 c000889900 -- KEVENT.Header.anonymous_0.anonymous_0.Type
        # 000002 c000888e00 c000889a00 -- KEVENT.Header.anonymous_0.Lock
        # 000001 c000888e00        -- KEVENT.Header.anonymous_0
        # 000001 c002bdc400
        # ff0000000000088e -- KEVENT
        # ff0000000000088f -- DISPATCHER_HEADER
        # ff00000000000890 -- _DISPATCHER_HEADER::*F98
        # ff00000000000891 -- _DISPATCHER_HEADER::*F98*0C
        # (x ^ 0xc0000000ff) ror 8

        def id64(sup):
            iterable = (item for item in bytearray(sup))

            # First consume the offset (FIXME: we only support 2 bytes for now...)
            by = builtins.next(iterable)
            if le([by]) & 0x80:
                offset = le([by] + [builtins.next(iterable)])
                offset ^= 0x8000
            else:
                offset = 0

            # Now we can grab our length
            length = le([builtins.next(iterable), builtins.next(iterable)])
            rest = [item for item in iterable]

            if len(rest) % 3 == 0:
                count, mask = 3, 0x8000ff

            elif len(rest) % 5 == 0:
                count, mask = 5, 0xc0000000ff

            else:
                raise NotImplementedError(u"{:s}.sup_opstruct({!r}) -> id64 : Error decoding supval from parameter.".format('.'.join([__name__, node.__name__]), sup))

            iterable = (item for item in rest)
            chunks = [item for item in zip(*(count * [iterable]))]

            #length = le(chunks.pop(0))
            if len(chunks) != length:
                raise internal.exceptions.SizeMismatchError(u"{:s}.sup_opstruct(\"{:s}\") -> id64 : Number of chunks ({:d}) does not match the extracted length ({:d}). These chunks are {!r}.".format('.'.join([__name__, node.__name__]), internal.utils.string.tohex(sup), len(chunks), length, [bytes().join(item) for item in chunks]))
            res = map(le, chunks)
            res = map(functools.partial(operator.xor, mask), res)
            return offset, [ror(item, 8, 64) for item in res]

        offset, items = id64(sup) if bit64Q else id32(sup)
        return offset, [Fidentifier(item) for item in items]

    @internal.utils.multicase(ea=internal.types.integer)
    @classmethod
    def aflags(cls, ea):
        '''Return the additional flags for the instruction at the address `ea`.'''
        NALT_AFLAGS = getattr(idaapi, 'NALT_AFLAGS', 8)
        if hasattr(idaapi, 'get_aflags'):
            return idaapi.get_aflags(ea)
        return internal.netnode.alt.get(idaapi.ea2node(ea) if hasattr(idaapi, 'ea2node') else ea, NALT_AFLAGS)
    @internal.utils.multicase(ea=internal.types.integer, mask=internal.types.integer)
    @classmethod
    def aflags(cls, ea, mask):
        '''Return the additional flags for the instruction at the address `ea` masked with the integer provided by `mask`.'''
        return cls.aflags(ea) & mask
    @internal.utils.multicase(ea=internal.types.integer, mask=internal.types.integer, value=internal.types.integer)
    @classmethod
    def aflags(cls, ea, mask, value):
        '''Set the additional flags for the instruction at address `ea` using the provided `mask` and `value`.'''
        NALT_AFLAGS = getattr(idaapi, 'NALT_AFLAGS', 8)
        result, flags = cls.aflags(ea, ~mask), value & mask
        if hasattr(idaapi, 'set_aflags'):
            return idaapi.set_aflags(ea, result | flags)
        return internal.netnode.alt.set(idaapi.ea2node(ea) if hasattr(idaapi, 'ea2node') else ea, NALT_AFLAGS, result | flags)

    @classmethod
    def alt_opinverted(cls, ea, opnum):
        '''Return whether the operand `opnum` at the address `ea` has its sign inverted or not.'''
        AFL_SIGN0, AFL_SIGN1 = 0x100000, 0x200000

        # Verify that we were given an operand number that has been tested before,
        # and log it if we haven't. Although it's likely that IDA will consider
        # all of the operands that follow the second operand as inverted once the
        # inversion has been applied by the user, we log this just to be safe and
        # let the user know that we're making an assumption here.
        if opnum not in {0, 1, 2}:
            result = cls.aflags(ea)
            logging.info(u"{:s}.alt_opinverted({:#x}, {:d}) : Fetching the inversion state for the operand ({:d}) of the instruction at {:#x} has not been tested (aflags={:#x}).".format('.'.join([__name__, cls.__name__]), ea, opnum, opnum, ea, result))

        # Grab the altval containing the additional flags for the given address
        # masked with the bits that we plan on checking.
        else:
            result = cls.aflags(ea, AFL_SIGN0 | AFL_SIGN1)

        # Now we just need to figure out which flag we need to use for the
        # operand that was chosen, and then we can check its mask.
        flag = AFL_SIGN1 if opnum else AFL_SIGN0
        return result & flag == flag

    @classmethod
    def alt_opnegated(cls, ea, opnum):
        '''Return whether the operand `opnum` at the address `ea` has its value negated or not.'''
        AFL_BNOT0, AFL_BNOT1 = 0x100, 0x200
        AFL_BNOTX = AFL_BNOT0 | AFL_BNOT1

        # Verify that we were given an operand number that has been tested before,
        # and if not then log it. Although it's totally plausible that the negation
        # of the second operand will affect all of the other operands that follow
        # it when the negation is applied by the user, we do this log just to be
        # safe and let the user know that we're making an assumption.
        if opnum not in {0, 1, 2}:
            result = cls.aflags(ea)
            logging.info(u"{:s}.alt_opnegated({:#x}, {:d}) : Fetching the negation state for the operand ({:d}) of the instruction at {:#x} has not been tested (aflags={:#x}).".format('.'.join([__name__, cls.__name__]), ea, opnum, opnum, ea, result))

        # Grab the altval containing the additional flags for the given address
        # masked with the bits that we want to check.
        else:
            result = cls.aflags(ea, AFL_BNOT0 | AFL_BNOT1)

        # Similar to the alt_opinverted function, we just need to figure out
        # the flag to use for the operand number that was chosen so that we
        # check its the aflags against the correct mask.
        flag = AFL_BNOT1 if opnum else AFL_BNOT0
        return result & flag == flag

class strpath(object):
    """
    This namespace contains utilities that interact with a structure path
    which includes the generation of filters, etc.

    A structure path is a tuple composed of `(sptr, mptr, offset)`.
    """
    @classmethod
    def candidates(cls, sptr, offset):
        '''Given the specified offset, return the `(sptr, [mptrs], offset)` that it can point to.'''
        SF_VAR, SF_UNION = getattr(idaapi, 'SF_VAR', 0x1), getattr(idaapi, 'SF_UNION', 0x2)

        # Define a closure that checks whether the given member contains the specified
        # offset and then translates it. If sptr is a union, the offset needs to come
        # before the end of the member. If it's variable-sized and the last member's
        # id matches the mptr, then the offset should come after the last member. If
        # both mptr.soff and mptr.eoff are the same then the member itself is
        # variable-sized and requires us to check that the offset is in front of it.
        # Anything else requires us to just check against the member's boundaries.
        def contains(sptr, mptr, offset):
            '''Return whether the given `mptr` contains the specified offset.'''
            if sptr.props & SF_UNION:
                return offset < mptr.eoff
            elif mptr.soff == mptr.eoff:
                return mptr.eoff <= offset
            elif sptr.props & SF_VAR and sptr.memqty > 0 and sptr.get_member(sptr.memqty - 1).id == mptr.id:
                return mptr.soff <= offset
            return mptr.soff <= offset < mptr.eoff

        # First grab all the members and then use them to collect the boundaries for
        # all of the candidate members that are within the requested offset.
        members = [sptr.get_member(index) for index in builtins.range(sptr.memqty)]
        if any([0 <= offset < idaapi.get_struc_size(sptr), sptr.props & SF_VAR]):
            candidates = [mptr for mptr in members if contains(sptr, mptr, offset)]
        else:
            candidates = members if sptr.props & SF_UNION else members[:1] if offset < 0 else members[-1:]

        # We just need to return our candidates, and use the offset from wherever they
        # begin to translate the offset we were given so that it's relative to the
        # member. If we're a union, then the members start at 0 and our offset is always
        # going to be the same. No candidates, means we have no members to return.
        if candidates:
            delta = 0 if sptr.props & SF_UNION else next(mptr.soff for mptr in candidates)
            assert(sptr.props & SF_UNION or all(delta == mptr.soff for mptr in candidates))
            return sptr, candidates, offset - delta
        return sptr, [], offset

    @classmethod
    def collect(cls, struc, Fcollect):
        '''This is a utility function that starts at the given sptr in `struc` and consumes either an `sptr`, `mptr`, or an `offset` while adding completed items via `Fcollect`.'''
        SF_UNION = getattr(idaapi, 'SF_UNION', 0x2)

        sptr, mptr, offset = struc, None, 0
        while True:
            try:
                item = (yield sptr)

            # We're being told that we need to gtfo so save what's left and exit our loop.
            except GeneratorExit:
                Fcollect((sptr, mptr, offset))
                break

            # If we were given an offset and we have a member, then we can just update our
            # current offset with it. This allows one to consolidate multiple offsets, but
            # as there's a chance of there being no member defined yet will result in an
            # error as soon as they try to transition to one.
            if isinstance(item, internal.types.integer):
                offset += item

            # If we were given a structure and it's the same as the one that we're on,
            # then that means the user wants the size to be used for the member.
            elif isinstance(item, idaapi.struc_t) and item.id == sptr.id:
                mptr = item

            # If we were given a structure, then we need to check that it matches the
            # structure that we expect. If so then we can switch into it.
            elif isinstance(item, idaapi.struc_t) and idaapi.get_sptr(mptr) and idaapi.get_sptr(mptr).id == item.id:
                Fcollect((sptr, mptr, offset))
                sptr, mptr, offset = item, None, 0

            # If we were given a member, then we need to check to see if we've encountered
            # it yet for the current result. We also need to check to ensure it's within
            # the current sptr that we're processing in order to log a warning if otherwise.
            elif isinstance(item, idaapi.member_t):
                expected = idaapi.get_member_struc(idaapi.get_member_fullname(item.id))

                # If we haven't assigned an item into the mptr and the item's parent is the
                # same as our current sptr, then we can just assign it and move on.
                if mptr is None and expected.id == sptr.id:
                    mptr = item

                # If we've already assigned the mptr and the item's parent is the same
                # as our current sptr, then we issue a warning and re-assign it.
                elif expected.id == sptr.id:
                    logging.warning(u"{:s}.collect({:#x}, result={!s}) : Overwriting {:s} \"{:s}\" ({:#x}) of collected results with {:s} \"{:s}\" ({:#x}) due to it belonging to the current {:s} \"{:s}\" ({:#x}).".format('.'.join([__name__, cls.__name__]), struc.id, Fcollect, mptr.__class__.__name__, internal.utils.string.escape(internal.netnode.name.get(mptr.id), '"'), mptr.id, item.__class__.__name__, internal.utils.string.escape(internal.netnode.name.get(item.id), '"'), item.id, sptr.__class__.__name__, internal.utils.string.escape(internal.netnode.name.get(sptr.id), '"'), sptr.id))
                    mptr = item

                # If we got here we need to append our state. However, mptr is None and so
                # we need to fix it up so that it points to an actual member before reset.
                elif mptr is None:
                    mptr = idaapi.get_member(sptr, offset)
                    Fcollect((sptr, mptr, offset - (0 if sptr.props & SF_UNION else mptr.soff)))
                    sptr, mptr, offset = expected, item, 0

                # If we're here, then our sptr doesn't match and we need to append our
                # state to our current results and then transition to the new sptr.
                else:
                    Fcollect((sptr, mptr, offset))
                    sptr, mptr, offset = expected, item, 0

            # If we were given the completely wrong type (or wrong order), and we have no
            # idea what to do. So, add our current position and raise an exception.
            else:
                Fcollect((sptr, mptr, offset))
                description = [item.__class__.__module__, item.__class__.__name__] if hasattr(item.__class__, '__module__') else [item.__class__.__name__]
                raise internal.exceptions.InvalidTypeOrValueError(u"{:s}.collect({:#x}, result={!s}) : Unable to continue collecting results due to the received item ({!r}) being an unsupported type ({!s}).".format('.'.join([__name__, cls.__name__]), struc.id, Fcollect, item, '.'.join(description)))
            continue
        return

    @classmethod
    def fullname(cls, path, sep='.'):
        '''Return the given structure path as an easily-read string.'''
        result = []
        for sptr, mptr, offset in path:
            if mptr:
                _, fullname, owner = idaapi.get_member_by_id(mptr.id)
                name, msize, size = idaapi.get_member_name(mptr.id), idaapi.get_data_elsize(mptr.id, mptr.flag), idaapi.get_member_size(mptr)
                sname, oname = (internal.netnode.name.get(ptr.id) for ptr in [sptr, owner])
                arrayQ, hindex = msize != size, (size - 1) // msize
                index, item = divmod(offset, msize) if arrayQ else (0, offset)
                index, offset = (index, item) if index * msize < size or mptr.soff == mptr.eoff else (hindex, item + (offset - hindex * msize))
                item = "{:s}{:s}{:s}".format(fullname if not result else name if owner.id == sptr.id else "{{ERR!{:s}|{:s}}}{:s}".format(sname, oname, name), "[{:d}]".format(index) if arrayQ else '', "({:+#x})".format(offset) if offset else '' if mptr else "{:+#x}".format(offset))
            elif sptr:
                item = ''.join([internal.netnode.name.get(sptr.id), "({:+#x})".format(offset) if offset else ''])
            else:
                item = "{{ERR!{:+#x}}}".format(offset)
            result.append(item)
        return sep.join(result) if sep else result

    @classmethod
    def format(cls, sptr, mptr, offset=0):
        '''Return the description of an individual item for a structure path.'''
        MF_UNIMEM = getattr(idaapi, 'MF_UNIMEM', 0x2)

        sptr_t, mptr_t = idaapi.struc_t if sptr is None else sptr.__class__, idaapi.member_t if mptr is None else mptr.__class__
        sptr_description = '.'.join([sptr_t.__module__, sptr_t.__name__] if hasattr(sptr_t, '__module__') else [sptr_t.__name__])
        mptr_description = '.'.join([mptr_t.__module__, mptr_t.__name__] if hasattr(mptr_t, '__module__') else [mptr_t.__name__])
        offset_description = "{:+#x}".format(offset) if offset else ''

        # If there's no mptr or they're the same, then we're simply a structure and an offset.
        if sptr and (mptr is None or sptr.id == mptr.id):
            sname = internal.netnode.name.get(sptr.id) or ''
            return "{:s}({:#x}, \"{:s}\"){:s}".format(sptr_description, sptr.id, internal.utils.string.escape(sname, '"'), offset_description)

        # If sptr is None, then we simply figure it out for them and try again.
        elif not sptr:
            _, _, sptr = idaapi.get_member_by_id(mptr.id)
            return cls.format(sptr, mptr, offset)

        # Now we need to check that the member is actually a member. So we
        # grab its name, and try and get the member by its id.
        sname, mname = ((internal.netnode.name.get(item.id) or '') for item in [sptr, mptr])
        result = idaapi.get_member_by_id(mptr.id)

        # If we got something then we need to check that the mptr is related
        # to the sptr by comparing it to the member's structure id that we got.
        if result and sptr.id == result[2].id:
            name = mname[len(sname):]
            return "{:s}({:#x}, {:#x}{:s} {:s}={:#x}{:s})".format(mptr_description, mptr.id, sptr.id, internal.utils.string.escape(name, '"'), 'index' if mptr.props & MF_UNIMEM else 'offset', mptr.soff, offset_description)

        # Anything else means the member is not part of the structure and we
        # clarify that by listing the full name of the member and the parent.
        member = "{:s}({:#x}, \"{:s}\" {:s}={:#x}{:s})".format(mptr_description, mptr.id, internal.utils.string.escape(mname, '"'), 'index' if mptr.props & MF_UNIMEM else 'offset', mptr.soff, offset_description)
        parent = "{:s}({:#x}, \"{:s}\")".format(sptr_description, sptr.id, internal.utils.string.escape(sname, '"'))
        return ' '.join(['(ERROR)', parent, 'is unrelated to', member])

    @classmethod
    def resolve(cls, Fcollect, sptr, offset):
        """Start resolving a path at the given offset of sptr whilst allowing the caller to make decisions at each member.

        The `Fcollect` parameter contains the callable that will be used to store each path item.
        """
        SF_UNION = getattr(idaapi, 'SF_UNION', 0x2)

        # Seed some variables that we'll use to emit some friendlier error messages.
        count, position = 0, 0
        formatlog = functools.partial(u"{:s}.resolve(Fcollect={:s}, {:#x}, {:+#x}) : {:s}".format, '.'.join([__name__, cls.__name__]), '...', sptr.id, offset)

        description = "{:s} ({:#x}) of size ({:#x})".format('union' if sptr.props & SF_UNION else 'structure', sptr.id, idaapi.get_struc_size(sptr))
        logging.debug(formatlog(u"Resolving path for the {:s} towards the offset {:+#x}.".format(description, offset)))

        # Continue looping while we still have choices left. We start each iteration
        # by figuring out what members are at the chosen offset for the user to choose.
        # If there aren't any candidates, then add our current position and leave.
        while sptr:
            sptr, candidates, carry = cls.candidates(sptr, offset)

            # Give the caller the candidates and the offset we aimed for
            # for so that they can either make a choice or re-adjust it.
            [ logging.debug(formatlog(u"Potential {:s}candidate ({:d} of {:d}) for item {:d} (offset {:#x}{:+#x}) of path : {:s}".format('union ' if sptr.props & SF_UNION else '', 1 + index, len(candidates), count, position, offset, cls.format(sptr, item)))) for index, item in enumerate(candidates) ]
            try:
                choice, shift = (yield (sptr, candidates, carry))

            # If we're being told to clean up, then ignore the decision, use
            # the carry value that we determined on their behalf and quit.
            except GeneratorExit:
                mptr, offset = None, carry
                break

            # If they didn't give us a value to shift by, then assume they want the
            # offset that we used to determine the member candidates with.
            else:
                offset = carry if shift is None else shift

            # If we weren't given a choice then we have to make some decisions on
            # their behalf. If there was only one candidate, then use it. Otherwise
            # we'll just do what they tell us and use None (which will terminate).
            if not choice and len(candidates or []) in {0, 1}:
                mptr = candidates[0] if candidates else None

            # If their choice is one of our candidates, then we'll take it.
            elif isinstance(choice, idaapi.member_t) and choice.id in {item.id for item in (candidates or [])}:
                mptr = choice

            # If their choice is the structure (which is not a candidate), then they're
            # choosing its size. We're friendly, though, and honor their desired offset.
            elif choice and choice.id == sptr.id:
                mptr = choice
                break

            # Anything else is because their choice was wrong or we're not going to
            # decide for them. So we need to freak out. If they want to recover, the
            # they'll will need to compare the length of what they gave us with the
            # results we've been aggregating in order to determine what happened.
            else:
                description = 'union' if sptr.props & SF_UNION else "{:+#x} structure".format(idaapi.get_struc_size(sptr.id))
                message = "no valid candidates being chosen ({:s})".format(', '.join(map("{:#x}".format, (mptr.id for mptr in candidates)))) if choice is None else "an invalid candidate ({:s}) being chosen".format("{:#x}".format(choice.id) if hasattr(choice, 'id') else "{!r}".format(choice))
                raise internal.exceptions.MemberNotFoundError(formatlog(u"Path terminated at item {:d} (offset {:#x}{:+#x}) of {:s} ({:#x}) due to {:s}.".format(count, position, offset, description, sptr.id, message)))

            # Now that we determined the mptr for the user's choice, figure out the
            # member's total size and it's member size. From this we'll check if it's
            # actually an array, and determine its maximum index as necessary.
            size, msize = (idaapi.get_member_size(mptr), idaapi.get_data_elsize(mptr.id, mptr.flag)) if mptr else (0, 1)
            arrayQ, maxindex = mptr and msize != size, (size - 1) // msize

            # Using their offset and the mptr's member size, calculate what index the user
            # referenced. We then adjust the index so that it's clamped at the maximum possible
            # array index in order to carry the correct offset into the next item we receive.
            uindex, ubytes = divmod(offset, msize) if arrayQ else (0, offset)
            index, bytes = (uindex, ubytes) if any([uindex * msize < size, arrayQ and mptr.soff == mptr.eoff]) else (maxindex, ubytes + (offset - maxindex * msize))
            logging.debug(formatlog(u"Sender chose {:s} which will result in {:s}carrying offset {:+#x}.".format(cls.format(sptr, mptr, offset), "preserving offset {:+#x} (index {:d}) and ".format(index * msize, index) if arrayQ else '', bytes)))

            # If we've landed on a member (get_sptr returns None from either the mptr
            # being invalid or it not being a structure), then there's nothing to
            # do but exit our loop with whatever state the user has given us.
            if not idaapi.get_sptr(mptr):
                break

            # Store the caller's choice but adjust it by the offset that we received
            # (relative to carry) and the index that needs to be preserved in the item.
            Fcollect((sptr, mptr, (offset - carry) + index * msize))

            # Now we'll update our state for error messages, and then transition to the next
            # item while adjusting our offset so that way it points to the next member.
            count, position = count + 1, position + (0 if sptr.props & SF_UNION else mptr.soff) + index * msize
            sptr, offset = idaapi.get_sptr(mptr), bytes

        # No path members left to process, so the whole path should be resolved and we
        # only need to add the last member that was determined.
        Fcollect((sptr, mptr, offset))
        count, position = count + 1, position + (0 if sptr.props & SF_UNION else mptr.soff if mptr else 0)

        # Before we go, send the user off with a friendly message to thank them for their business.
        if mptr is None:
            left, right = 0, idaapi.get_struc_size(sptr)
            description = ' '.join(["{:s} ({:#x})".format('union' if sptr.props & SF_UNION else 'structure', sptr.id), "{:#x}<>{:+#x}".format(left, right)])
        else:
            left, right = 0 if sptr.props & SF_UNION else mptr.soff, mptr.eoff
            description = ' '.join(["field ({:#x})".format(mptr.id), "{:#x}<>{:s}".format(left, "{:+#x}({:+#x})".format(right, idaapi.get_struc_size(sptr)) if mptr.soff == mptr.eoff else "{:+#x}".format(right))])
        logging.debug(formatlog(u"Path terminated at item {:d} (offset {:#x}{:+#x}) with {:s}.".format(count, position, offset, description)))

    @classmethod
    def calculate(cls, delta=0, Fcollect=operator.truth):
        '''This is just a utility function that consumes `(sptr, mptr, offset)` items and yields the resulting delta to get to it.'''
        SF_UNION = getattr(idaapi, 'SF_UNION', 0x2)

        # Spin in while always returning the current delta that we've calculated on. If we
        # received an empty value, then yield our state because that's all we're good for.
        while True:
            item = (yield delta)
            if item is None:
                continue

            # This is super simple as we only need to check if our sptr is a union. We
            # don't care about validating this path because someone else should've.
            sptr, mptr, offset = item
            delta = sum([delta, 0 if sptr.props & SF_UNION else 0 if mptr is None else idaapi.get_struc_size(mptr) if mptr.id == sptr.id else mptr.soff, offset])
            Fcollect((sptr, mptr, offset))

            # If our path has actually stopped at a field, then we can just break out
            # of our loop because there's nothing that can change anything
            if isinstance(mptr, idaapi.member_t) and not idaapi.get_sptr(mptr):
                break
            continue

        # This loop just continuously yields the delta because technically our path is
        # over since we've already encountered a non-structure field.
        while True:
            (yield delta)
        return

    @classmethod
    def flail(cls, suggestion):
        '''A utility function that continuously yields decisions from a suggestion until there are no more available.'''
        flailer = {}

        # First we'll initialize our dictionary that we'll use to lookup decisions
        # that the user gave us in the suggested path and collect our description.
        suggestion_description = []
        for sptr, mptr, offset in suggestion:
            items = flailer.setdefault(sptr.id, [])
            items.append((mptr, offset))
            suggestion_description.append(cls.format(sptr, mptr, offset))

        # Now we can enter our main loop that just looks up the current structure
        # in our table and chooses the default candidate when it doesn't exist.
        sptr, candidates, carry = (yield)
        while flailer:
            items = flailer[sptr.id] if flailer.get(sptr.id, []) else flailer.pop(sptr.id, [])

            # If we know about this structure, then grab the element out of it and
            # adjust our offset by the delta we found within our suggestion.
            if items:
                mptr, delta = items.pop(0)

            # If there's nothing to flail with, then carry with the default item.
            else:
                mptr, delta = None, 0

            # If our current item has an offset, then log that we're adjusting it.
            if mptr and carry != delta:
                logging.debug(u"{:s}.flail([{:s}]) : The suggested path item {:s} does not match {:s} and its difference ({:+#x}) will likely be carried into the next member.".format('.'.join([__name__, cls.__name__]), "[{:s}]".format(', '.join(suggestion_description)), cls.format(sptr, mptr, delta), cls.format(sptr, None, carry), delta))

            # Send it off.. pray that our flailing accomplished something.
            sptr, candidates, carry = (yield (sptr, mptr, carry))

        # We terminated, so let the caller know where we actually stopped at.
        logging.debug(u"{:s}.flail([{:s}]) : Flailing ended at {:s} with {:d} possible candidates ({:s}).".format('.'.join([__name__, cls.__name__]), "[{:s}]".format(', '.join(suggestion_description)), cls.format(sptr, None, carry), len(candidates), ', '.join("{:#x}".format(item.id) for item in candidates)))

    @classmethod
    def of_tids(cls, offset, tids):
        '''Just a utility functions that uses the provided offset and a list of tids (`tid_array`) to return the complete path.'''
        iterable = (tid for tid in tids)

        # Start out by grabbing the first tid and converting it to an sptr before we start.
        sid = builtins.next(iterable, idaapi.BADADDR)
        sptr = idaapi.get_struc(sid)
        if sptr is None:
            raise internal.exceptions.StructureNotFoundError(u"{:s}.of_tids({:#x}, {:s}) : Unable to find a structure for the given identifier ({:#x}).".format('.'.join([__name__, cls.__name__]), offset, "[{:s}]".format(', '.join(map("{:#x}".format, tids))), sid))

        # Define a class that we'll use to aggregate our results from visit_stroff_fields.
        class visitor_t(idaapi.struct_field_visitor_t):
            def visit_field(self, sptr, mptr):
                calculator.send((sptr, mptr, 0))
                return 0

        # We plan on both collecting and calculating our path so that we can figure out how
        # we should resolve what IDA spits back at us. So, seed a calculator for our results.
        visitorpath = []
        calculator = cls.calculate(0, visitorpath.append)
        visitordelta = builtins.next(calculator)

        visitor = visitor_t()
        length, path = len(tids), idaapi.tid_array(len(tids))
        for index, item in enumerate(tids):
            path[index] = item
        disp = idaapi.sval_pointer()
        disp.assign(offset)
        visit_zero = 1

        res = idaapi.visit_stroff_fields(visitor, path, length, disp, visit_zero) if idaapi.__version__ < 7.0 else  idaapi.visit_stroff_fields(visitor, tids, disp.cast(), visit_zero)
        leftover, visitordelta = disp.value(), builtins.next(calculator)
        calculator.close()

        if idaapi.BADADDR & offset != idaapi.BADADDR & (visitordelta + leftover):
            callable = idaapi.visit_stroff_fields
            raise internal.exceptions.DisassemblerError(u"{:s}.of_tids({:#x}, {:s}) : Expected the call to `{:s}` to return {:#x} bytes but {:#x}{:+#x} ({:#x}) was returned instead.".format('.'.join([__name__, cls.__name__]), offset, "[{:s}]".format(', '.join(map("{:#x}".format, tids))), '.'.join(getattr(callable, attribute) for attribute in ['__module__', '__name__'] if hasattr(callable, attribute)), offset, visitordelta, leftover, visitordelta + leftover))

        # Now we can rely on cls.resolve to figure out where our decisions actually belong. We can
        # target the offset the user gave us because IDA did all of the work for the path, and we
        # only need to figure out which fields the offset is applied to.
        result = []
        calculator = cls.calculate(0, result.append)
        resolver = cls.resolve(calculator.send, sptr, offset - leftover)
        flailer = cls.flail(visitorpath)

        resultdelta, _ = (builtins.next(item) for item in [calculator, flailer])

        # Begin resolving using the flailer till there's nothing left. We also ensure that we
        # always return an item within the bounds of the structure so we get as far as we can.
        sptr, candidates, carry = builtins.next(resolver)
        try:
            while True:
                owner, choice, zero = flailer.send((sptr, candidates, carry))
                if choice and choice.id not in {item.id for item in candidates}:
                    logging.info(u"{:s}.of_tids({:#x}, {:s}) : Ignoring the recommended choice ({:#x}) for index {:d} at offset ({:+#x}) as it was not in the list of candidates ([{:s}]).".format('.'.join([__name__, cls.__name__]), offset, "[{:s}]".format(', '.join(map("{:#x}".format, tids))), choice.id, len(result), builtins.next(calculator), ', '.join("{:#x}".format(item.id) for item in candidates)))
                    break

                sptr, candidates, carry = resolver.send((choice, carry))

            # Always complete our path with whatever the default is.
            while True:
                resolver.send((None, None))

        except (StopIteration, internal.exceptions.MemberNotFoundError):
            pass

        finally:
            flailer.close(), resolver.close()
            resultdelta, _ = builtins.next(calculator), calculator.close()

        # Now we can check our delta which contains the full path of the result against the
        # sum of the visitordelta and the leftover bytes that IDA gave us.
        if resultdelta == visitordelta:
            logging.debug(u"{:s}.of_tids({:#x}, {:s}) : Successfully resolved {:#x}{:+#x} bytes for the path {:s} to {:s}.".format('.'.join([__name__, cls.__name__]), offset, "[{:s}]".format(', '.join(map("{:#x}".format, tids))), resultdelta, leftover, cls.fullname(visitorpath), cls.fullname(result)))

        # Otherwise our resolved path was not completely resolved. Still, we'll honor what IDA
        # gave us by adjusting the visitor path despite it being busted.
        else:
            logging.info(u"{:s}.of_tids({:#x}, {:s}) : The delta ({:#x}) for the resolved path does not match the expected delta ({:#x}).".format('.'.join([__name__, cls.__name__]), offset, "[{:s}]".format(', '.join(map("{:#x}".format, tids))), resultdelta, visitordelta))
            logging.debug(u"{:s}.of_tids({:#x}, {:s}) : Truncated {:+#x} bytes from the path {:s} resulting in {:s}.".format('.'.join([__name__, cls.__name__]), offset, "[{:s}]".format(', '.join(map("{:#x}".format, tids))), resultdelta, cls.fullname(visitorpath), cls.fullname(result)))

        # If we were unable to resolve a path, then we explicitly trust the visitorpath.
        return result or visitorpath

    @classmethod
    def to_tids(cls, path):
        '''This is just a utility function that converts the final path into a list of tids (`tid_array`) containing the decisions required for unions to be displayed properly.'''
        SF_UNION = getattr(idaapi, 'SF_UNION', 0x2)

        # First we'll collect all of the identifiers that we were given
        # within our path since that's all we really care about. Then we
        # need to extract the first sptr, and then put it back so we can
        # process only the members that are part of a union.
        iterable = ((sptr, mptr) for sptr, mptr, _ in path)
        item = builtins.next(iterable)
        sptr, _ = item
        identifiers = [sptr.id]
        iterable = itertools.chain([item], iterable)

        # Now we can process all of the members in our iterator that contain
        # a user-made decision (represented by being part of a union) and
        # then just combine them into a single list of our items to return.
        members = [mptr.id for sptr, mptr in iterable if sptr.props & SF_UNION and mptr]
        return identifiers + members

    @classmethod
    def suggest(cls, struc, suggestion):
        '''This takes a path given by the user and returns the resulting path along with its delta.'''

        # We first need to convert the path that the user gave us into the actual
        # path that we'll apply to the operand. We also need to calculate the delta
        # so we'll just connect our collector to our calculator which will then
        # add any items that get processed to our items.
        result, items = [], [item for item in suggestion]
        calculator = cls.calculate(0, result.append)
        collector = cls.collect(struc, calculator.send)

        # Now we can start both of them so we can feed inputs to our collector
        # until we're asked to stop. We keep track of the last sptr to ensure
        # that we don't send two mptrs in a row for the exact same structure.
        delta, sptr = (builtins.next(coro) for coro in [calculator, collector])
        try:
            # We leave our items as a list so that if an error occurs, we can
            # better explain what we were unable to process.
            last = sptr
            while items:
                item = items.pop(0)

                # If our item is a structure or a member, then we need to convert
                # it into either an idaapi.struc_t or an idaapi.member_t.
                if hasattr(item, 'ptr'):
                    mptr = item.ptr

                # If it's a string and the previous element was an mptr, then we need
                # to transition to the last member's type (sptr) and then look it up.
                elif isinstance(item, internal.types.string) and isinstance(last, idaapi.member_t):
                    last = idaapi.get_sptr(last)
                    sptr = collector.send(last)
                    mptr = idaapi.get_member_by_name(sptr, internal.utils.string.to(item))

                # If it's a string, then we can just look it up in our current
                # sptr to figure out which member_t it is.
                elif isinstance(item, internal.types.string):
                    mptr = idaapi.get_member_by_name(sptr, internal.utils.string.to(item))

                # Anything else should by one of the native types or an offset.
                else:
                    mptr = item

                # Submit it to the collector and save it away if it's not an integer.
                sptr, last = collector.send(mptr), last if isinstance(mptr, internal.types.integer) else mptr

        # If we received an exception, then that's because there was a busted type
        # in the collected path which we'll need to add back to our list.
        except internal.exceptions.InvalidTypeOrValueError as exc:
            ok, items = False, [mptr] + items
            logging.debug(u"{:s}.suggestion({:#x}, {!r}) : Collection was terminated with {:d} items left ({!r}) due to an invalid type ({!r}).".format('.'.join([__name__, cls.__name__]), struc.id, suggestion, len(items), items, mptr))

        # If we had no issues, then we only have to do one thing
        else:
            ok, _ = True, collector.close()

        # We should now be able to grab our delta out of the calculator, and then
        # we can close it before displaying what suggestions actually worked.
        finally:
            delta, _ = builtins.next(calculator), calculator.close()

        # Now we can check for any issues that happened while collecting their path.
        suggested = (''.join(['.'.join(map("{:#x}".format, [sptr.id, mptr.id] if mptr else [sptr.id])), "{:+#x}".format(offset) if offset else '']) for sptr, mptr, offset in result)
        suggestion_description = [item for item in itertools.chain(suggested, map("{!r}".format, items))]
        if ok:
            [ logging.debug(u"{:s}.suggestion({:#x}, [{:s}]) : Successfully interpreted path suggestion at index {:d} as {:s}.".format('.'.join([__name__, cls.__name__]), struc.id, ', '.join(suggestion_description), index, cls.format(*item))) for index, item in enumerate(result) ]

        # Verify that our path is empty and that we successfully consumed everything.
        else:
            logging.warning(u"{:s}.suggestion({:#x}, [{:s}]) : There was an error trying to interpret the suggestions for the path and was truncated to {:s}.".format('.'.join([__name__, cls.__name__]), struc.id, ', '.join(suggestion_description), cls.fullname(result)))

        [ logging.info(u"{:s}.suggestion({:#x}, [{:s}]) : Unable to interpret path suggestion at index {:d} from {!r}.".format('.'.join([__name__, cls.__name__]), struc.id, ', '.join(suggestion_description), len(suggestion) - len(items) + index, item)) for index, item in enumerate(items) ]
        return delta, result

    @classmethod
    def guide(cls, goal, struc, suggestion):
        '''This tries to determine a complete path from the sptr in `struc` to the offset `goal` using `suggestion` as a sloppy (sorta) guidance.'''
        result, suggestion_description = [], [item for item in itertools.starmap(cls.format, suggestion)]

        # Now we have the suggested path and the delta that they're aiming at. All
        # they really did was give us a suggestion as guidance, so we need to resolve
        # it to make sure it makes sense and that way we can store it in our real path.
        calculator = cls.calculate(0, result.append)
        resolver = cls.resolve(calculator.send, struc, goal)
        delta = builtins.next(calculator)

        # Seed our resolver, and then use an index to figure out where we are in our
        # suggestion. If their suggestion is busted, then we'll later use this to flail
        # around and figure out what item they actually meant when we need a decision.
        (owner, candidates, carry) = builtins.next(resolver)
        index, (sptr, mptr, offset) = 0, (owner, None, 0)
        try:
            # Now we can process all the crap they might've given us in their suggestion.
            for index, (sptr, mptr, offset) in enumerate(suggestion):

                # If we don't have an mptr, then we use the offset we were given.
                if not mptr:
                    carry = carry + offset

                # If our choice is not one of the candidates, then we need to bail so that we
                # can start flailing trying to figure out what the suggestion actually meant.
                elif mptr.id not in {item.id for item in candidates}:
                    break

                # Our suggestion still makes sense, so send our choice to the resolver
                # with the adjusted offset and continue with the next suggestion.
                (owner, candidates, carry) = resolver.send((mptr, carry))
            index += 1

        # If our loop has terminated before resolving the path, then we still have some
        # suggestions that we need to consume. Log what's left, and proceed to the next loop.
        except StopIteration:
            Flogging, discard_reason = logging.debug, 'was unnecessary and will be reused when flailing'

        # If we received this exception, then the user is doing something crazy and wants an
        # invalid path. Bump up the logging level and just leave since we can't do anything.
        except internal.exceptions.MemberNotFoundError:
            logging.critical(u"{:s}.guide({:#x}, {:#x}, {:s}) : The suggested path was invalid for offset {:#x} and was truncated at index {:d} ({:s}).".format('.'.join([__name__, cls.__name__]), goal, struc.id, "[{:s}]".format(', '.join(suggestion_description)), goal, index, cls.fullname(result)))
            Flogging, discard_reason = logging.info, 'was discarded'

        # We are finally done and we can stop resolving things. Any other elements that are
        # left weren't actually needed to get to the goal the user wanted.
        else:
            Flogging, discard_reason = logging.debug, 'was not actually used'

        # If there's any suggestions left, then just log them so we can see what's left to do.
        finally:
            for rindex, item in enumerate(suggestion[index:]):
                Flogging(u"{:s}.guide({:#x}, {:#x}, {:s}) : The path suggestion at index {:d} {:s} {:s}.".format('.'.join([__name__, cls.__name__]), goal, struc.id, "[{:s}]".format(', '.join(suggestion_description)), index + rindex, cls.format(*item), discard_reason))

        # If we didn't end up processing all of our suggestions, then we need to flail using
        # everything that's left in case the user's path was busted and needs to be repaired.
        flailer = cls.flail(suggestion[index:])
        try:
            # Now we can start it and continue to choose candidates until there's none left.
            builtins.next(flailer)
            while True:
                sptr, mptr, offset = flailer.send((owner, candidates, carry))
                owner, candidates, carry = resolver.send((mptr, offset))

        # If we have no suggestions left or we've stopped. Then we should be good to go.
        except StopIteration:
            logging.debug(u"{:s}.guide({:#x}, {:#x}, {:s}) : Successfully processed {:d} suggestion{:s} and terminated at index {:d} after processing {:s}.".format('.'.join([__name__, cls.__name__]), goal, struc.id, "[{:s}]".format(', '.join(suggestion_description)), len(suggestion[index:]), '' if len(suggestion[index:]) == 1 else 's', len(result), cls.format(sptr, mptr, offset)))

        # If resolving gave us an exception, then we couldn't do anything with the suggestion
        # even when we were flailing when trying to use all of them.
        except internal.exceptions.MemberNotFoundError:
            logging.info(u"{:s}.guide({:#x}, {:#x}, {:s}) : The suggested path was invalid for offset {:#x} and was truncated at index {:d} ({:s}).".format('.'.join([__name__, cls.__name__]), goal, struc.id, "[{:s}]".format(', '.join(suggestion_description)), goal, len(result), cls.fullname(result)))

        # Completed flailing our arms around trying to make sense of the user's suggestion.
        finally:
            flailer.close()

        # At this point, there's absolutely nothing left to do but to keep choosing the
        # default member until the resolver is complete.
        try:
            while True:
                owner, candidates, carry = resolver.send((None, carry))

        # We're finally done resolving the path. The path is now complete and in our result.
        except StopIteration:
            pass

        # If we got an exception here, then we needed to make a choice but didn't. It's
        # okay, though, because the user's path was completely resolved.
        except internal.exceptions.MemberNotFoundError:
            logging.info(u"{:s}.guide({:#x}, {:#x}, {:s}) : The suggested path was terminated at index {:d} of the result with {:d} candidate{:s} left{:s}.".format('.'.join([__name__, cls.__name__]), goal, struc.id, "[{:s}]".format(', '.join(suggestion_description)), len(result), len(candidates), '' if len(candidates) == 1 else 's', " ({:s})".format(', '.join("{:#x}".format(item.id) for item in candidates) if candidates else '')))

        finally:
            resolver.close()

        # If our result is empty, then the path the user gave us didn't even come close to
        # the goal that they wanted. We did get a structure, though, so use it instead.
        result if result else calculator.send([owner, None, carry])

        # We should now have our result resolved so we can grab our delta to return it.
        delta, _ = builtins.next(calculator), calculator.close()
        return delta, result

class tinfo(object):
    """
    This namespace provides miscellaneous utilities for interacting
    with IDA's ``idaapi.tinfo_t``. This includes both extracting
    and modification of the information contained within it.
    """
    # A lookup table for how to process locations types within tinfo_t.
    location_table = {
        idaapi.ALOC_STACK: operator.methodcaller('stkoff'),
        idaapi.ALOC_STATIC: operator.methodcaller('get_ea'),
        idaapi.ALOC_REG1: operator.methodcaller('get_reginfo'),
        idaapi.ALOC_REG2: operator.methodcaller('get_reginfo'),
        idaapi.ALOC_RREL: internal.utils.fcompose(operator.methodcaller('get_rrel'), internal.utils.fthrough(operator.attrgetter('reg'), operator.attrgetter('off'))),
    }

    # Define a throwaway closure that we use for entering and recursing
    # into the location_table. This is needed because scattered types
    # are recursive, and we want to return everything that we can.
    def process_location(atype, location, table):
        F = table.get(atype, internal.utils.fidentity)
        if isinstance(location, idaapi.argpart_t):
            return atype, (F(location), location.off, location.size)
        return atype, F(location)

    # Our first user of process_location which handles any argloc_t items
    # that are stored within an iterator based around a vector.
    process_items = lambda vectorator, table, process=process_location: [ process(vectorator[index].atype(), vectorator[index], table) for index in builtins.range(vectorator.size()) ]

    # Now we can use these two closures to support scattered types.
    location_table[idaapi.ALOC_DIST] = internal.utils.fcompose(operator.methodcaller('scattered'), lambda scatter_t, process=process_items, table=location_table: process(scatter_t, table))

    # Custom types are supported...but not really.
    location_table[idaapi.ALOC_CUSTOM] = operator.methodcaller('get_custom')

    # Now we'll re-use the throwaway closure as an entrypoint to rip
    # the raw location information. This is needed because argloc_t
    # are weakly referenced when we iterate through them, so we use
    # our table to extract their information into gc'd references.
    @classmethod
    def location_raw(cls, loc, process=process_location, table=location_table):
        return process(loc.atype(), loc, table)

    # Now we can define our real entrypoint that will process a raw location
    # in order to convert an argloc_t into one of our symbolic types. We also
    # stash the process_location closure because we need a reference to it
    # in order to access the location_table with our entries.
    @classmethod
    def location(cls, size, architecture, loctype, locinfo, process=process_location):
        '''Return the symbolic location for the raw `loctype`, `locinfo`, and `size` on the given `architecture`.'''

        # This just contains an offset relative to the bottom of the args.
        if loctype == idaapi.ALOC_STACK and not hasattr(locinfo, '__iter__'):
            return location_t(locinfo, size)

        # This is just an address for the user to figure out on their own.
        elif loctype == idaapi.ALOC_STATIC:
            return locinfo

        # A single register and its offset. Offset seems to only be used
        # when using scattered (ALOC_DIST) argument location types.
        elif loctype == idaapi.ALOC_REG1 and not hasattr(locinfo, '__iter__'):
            ridx1, regoff = (locinfo & 0x0000ffff) >> 0, (locinfo & 0xffff0000) >> 16
            try: reg = architecture.by_indexsize(ridx1, size)
            except KeyError: reg = architecture.by_index(ridx1)
            return phrase_t(reg, regoff) if regoff else reg

        # A pair of registers gets returned as a list since they're contiguous.
        elif loctype == idaapi.ALOC_REG2:
            ridx1, ridx2 = (locinfo & 0x0000ffff) >> 0, (locinfo & 0xffff0000) >> 16
            try: reg1 = architecture.by_indexsize(ridx1, size // 2)
            except KeyError: reg1 = architecture.by_index(ridx1)

            try: reg2 = architecture.by_indexsize(ridx2, size // 2)
            except KeyError: reg2 = architecture.by_index(ridx2)

            # The 2nd register is the most-significant with the 1st being the least.
            return [reg2, reg1]

        # Seems to be a value relative to a register (reg+off) which we return
        # as a phrase_t if there's an offset, otherwise just the register.
        elif loctype in {idaapi.ALOC_RREL}:
            ridx, roff = locinfo
            try: reg = architecture.by_indexsize(ridx, size)
            except KeyError: reg = architecture.by_index(ridx)
            return phrase_t(reg, roff) if roff else reg

        # Scattered shit should really just be a list of things, and we
        # can just recurse into it in order to extract our results.
        elif loctype in {idaapi.ALOC_DIST}:
            F = lambda atype, item, offset, size: cls.location(size, architecture, atype, (item, offset, size))
            # XXX: we can't translate scattered_t because it's an empty vector
            #      and its stkoff() appears to be uninitialized.
            iterable = ( F(atype, *item) for atype, item in locinfo )
            return { offset : item for offset, item in iterable }

        # ALOC_REG1, but for argpart_t as a key-value pair since we handle the original further up.
        elif loctype == idaapi.ALOC_REG1:
            locinfo, offset, size = locinfo
            ridx1, regoff = (locinfo & 0x0000ffff) >> 0, (locinfo & 0xffff0000) >> 16
            try:
                reg = architecture.by_index(ridx1)
                while reg.size < regoff + size:
                    reg = architecture.promote(reg)

                if (reg.position, reg.bits) != (8 * regoff, 8 * size):
                    reg = partialregister_t(reg, 8 * regoff, 8 * size)
            except KeyError:
                reg = partialregister_t(architecture.by_index(ridx1), 8 * regoff, 8 * size)
            return offset, reg

        # This is ALOC_STACK, but for argpart_t we return it as a key-value pair.
        elif loctype == idaapi.ALOC_STACK:
            linfo, offset, size = locinfo
            return offset, location_t(linfo, size)

        # Return None if there wasn't a location type.
        elif loctype in {idaapi.ALOC_NONE}:
            return

        # FIXME: We're not supporting this because I've never used this fucker.
        elif loctype in {idaapi.ALOC_CUSTOM}:
            ltypes = {getattr(idaapi, attribute) : attribute for attribute in dir(idaapi) if attribute.startswith('ALOC_')}
            custom = locinfo.get_custom() if hasattr(locinfo, 'get_custom') else locinfo
            raise NotImplementedError(u"{:s}.location({:d}, {!r}, {:d}, {!r}, ...) : Unable to decode location of type {:s} that uses the specified information ({!s}).".format('.'.join([__name__, cls.__name__]), size, architecture, loctype, locinfo, "{:s}({:d})".format(ltypes[loctype], loctype) if loctype in ltypes else "{:d}".format(loctype), custom))

        # Anything else we just return, because we have no context to even
        # raise an exception that can inform the user about what happened.
        return locinfo

    # Now we can delete the closures we defined and its location_table, because
    # they're already attached to the function that needs them.
    del(process_location)
    del(process_items)

    @classmethod
    def function_details(cls, func, ti):
        '''Given a function location in `func` and its type information as `ti`, return the ``idaapi.tinfo_t`` and the ``idaapi.func_type_data_t`` that is associated with it.'''
        rt, ea = addressOfRuntimeOrStatic(func)

        # If our type is a function pointer, then we need to dereference it
        # in order to get the type that we want to extract the argument from.
        if rt and ti.is_funcptr():
            pi = idaapi.ptr_type_data_t()
            if not ti.get_ptr_details(pi):
                raise internal.exceptions.DisassemblerError(u"{:s}.function_details({:#x}, {!r}) : Unable to get the pointer target from the type ({!r}) at the specified address ({:#x}).".format('.'.join([__name__, cls.__name__]), ea, "{!s}".format(ti), "{!s}".format(ti), ea))
            tinfo = pi.obj_type

        # If our type is not a function pointer, but it is a pointer...then we
        # dereference it and raise an exception so the user knows it's not callable.
        elif rt and ti.is_ptr():
            tinfo = ti.get_pointed_object()
            raise internal.exceptions.MissingTypeOrAttribute(u"{:s}.function_details({:#x}, {!r}) : The target of the pointer type ({!r}) at the specified address ({:#x}) is not a function.".format('.'.join([__name__, cls.__name__]), ea, "{!s}".format(ti), "{!s}".format(tinfo), ea))

        # Otherwise this a function and we just use the idaapi.tinfo_t that we got.
        elif not rt and ti.is_func():
            tinfo = ti

        # Anything else is a type error that we need to raise to the user.
        else:
            raise internal.exceptions.InvalidTypeOrValueError(u"{:s}.function_details({:#x}, {!r}) : The type that was received ({!r}) for the specified function ({:#x}) was not a function type.".format('.'.join([__name__, cls.__name__]), ea, "{!s}".format(ti), "{!s}".format(ti), ea))

        # Now we can check to see if the type has details that we can grab the
        # argument type out of. If there are no details, then we raise an
        # exception informing the user.
        if not tinfo.has_details():
            raise internal.exceptions.MissingTypeOrAttribute(u"{:s}.function_details({:#x}, {!r}) : The type information ({!r}) for the specified function ({:#x}) does not contain any details.".format('.'.join([__name__, cls.__name__]), ea, "{!s}".format(ti), "{!s}".format(tinfo), ea))

        # Now we can grab our function details and return them to the caller.
        ftd = idaapi.func_type_data_t()
        if not tinfo.get_func_details(ftd):
            raise internal.exceptions.DisassemblerError(u"{:s}.function_details({:#x}, {!s}) : Unable to get the details from the type information ({!r}) for the specified function ({:#x}).".format('.'.join([__name__, cls.__name__]), ea, "{!s}".format(ti), "{!s}".format(tinfo), ea))
        return tinfo, ftd

    @classmethod
    def update_function_details(cls, func, ti, *flags):
        '''Given a function location in `func` and its type information as `ti`, yield the ``idaapi.tinfo_t`` and the ``idaapi.func_type_data_t`` that is associated with it and then update the function with the `flags` and ``idaapi.func_type_data_t`` that is sent back.'''
        rt, ea = addressOfRuntimeOrStatic(func)
        apply_tinfo = idaapi.apply_tinfo2 if idaapi.__version__ < 7.0 else idaapi.apply_tinfo

        # Similar to function_details, we first need to figure out if our type is a
        # function so that we can dereference it to get the information that we yield.
        if rt and ti.is_funcptr():
            pi = idaapi.ptr_type_data_t()
            if not ti.get_ptr_details(pi):
                raise internal.exceptions.DisassemblerError(u"{:s}.update_function_details({:#x}, {!r}) : Unable to get the pointer target from the type ({!r}) at the specified address ({:#x}).".format('.'.join([__name__, cls.__name__]), ea, "{!s}".format(ti), "{!s}".format(ti), ea))
            tinfo = pi.obj_type

        # If the previous case failed, then we're our type isn't related to a function
        # and we were used on a non-callable address. If this is the case, then we need
        # to raise an exception to let the user know exactly what happened.
        elif rt and ti.is_ptr():
            tinfo = ti.get_pointed_object()
            raise internal.exceptions.MissingTypeOrAttribute(u"{:s}.update_function_details({:#x}, {!r}) : The target of the pointer type ({!r}) at the specified address ({:#x}) is not a function.".format('.'.join([__name__, cls.__name__]), ea, "{!s}".format(ti), "{!s}".format(tinfo), ea))

        # Otherwise this a function and we just use the idaapi.tinfo_t that we got.
        elif not rt and ti.is_func():
            tinfo = ti

        # Anything else is a type error that we need to raise to the user.
        else:
            raise internal.exceptions.MissingTypeOrAttribute(u"{:s}.update_function_details({:#x}, {!r}) : The type that was received ({!r}) for the specified function ({:#x}) was not a function type.".format('.'.join([__name__, cls.__name__]), ea, "{!s}".format(ti), "{!s}".format(ti), ea))

        # Next we need to ensure that the type information has details that
        # we can modify. If they aren't there, then we need to bail.
        if not tinfo.has_details():
            raise internal.exceptions.MissingTypeOrAttribute(u"{:s}.update_function_details({:#x}, {!r}) : The type information ({!r}) for the specified function ({:#x}) does not contain any details.".format('.'.join([__name__, cls.__name__]), ea, "{!s}".format(ti), "{!s}".format(tinfo), ea))

        # Now we can grab our function details from the tinfo.
        ftd = idaapi.func_type_data_t()
        if not tinfo.get_func_details(ftd):
            raise internal.exceptions.DisassemblerError(u"{:s}.update_function_details({:#x}, {!r}) : Unable to get the details from the type information ({!r}) for the specified function ({:#x}).".format('.'.join([__name__, cls.__name__]), ea, "{!s}".format(ti), "{!s}".format(tinfo), ea))

        # Yield the function type along with the details to the caller and then
        # receive one back (tit-for-tat) which we'll use to re-create the tinfo_t
        # that we'll apply back to the address.
        ftd = (yield (tinfo, ftd))
        if not tinfo.create_func(ftd):
            raise internal.exceptions.DisassemblerError(u"{:s}.update_function_details({:#x}, {!r}) : Unable to modify the type information ({!r}) for the specified function ({:#x}).".format('.'.join([__name__, cls.__name__]), ea, "{!s}".format(ti), "{!s}".format(tinfo), ea))

        # If we were a runtime-linked address, then we're a pointer and we need
        # to re-create it for our tinfo_t.
        if rt:
            pi.obj_type = tinfo
            if not ti.create_ptr(pi):
                raise internal.exceptions.DisassemblerError(u"{:s}.update_function_details({:#x}, {!r}) : Unable to modify the pointer target in the type information ({!r}) for the specified function ({:#x}).".format('.'.join([__name__, cls.__name__]), ea, "{!s}".format(info), "{!s}".format(tinfo), ea))
            newinfo = ti

        # If it wasn't a runtime function, then we're fine and can just apply the
        # tinfo that we started out using.
        else:
            newinfo = tinfo

        # Finally we have a proper idaapi.tinfo_t that we can apply. After we apply it,
        # all we need to do is return the previous one to the caller and we're good.
        if not apply_tinfo(ea, newinfo, *itertools.chain(flags if flags else [idaapi.TINFO_DEFINITE])):
            raise internal.exceptions.DisassemblerError(u"{:s}.update_function_details({:#x}, {!r}) : Unable to apply the new type information ({!r}) to the specified function ({:#x}).".format('.'.join([__name__, cls.__name__]), ea, "{!s}".format(info), "{!s}".format(newinfo), ea))

        # Spinning on that dizzy edge.. I kissed her face and kissed her head..
        # And dreamed of all the ways.. That I had to make her glow. Why are you
        # so far way, she said why won't you ever know..that I'm in love with you.
        # That I'm in love with you.
        try:
            while True:
                ftd = yield (newinfo, ftd)

        # ...and now we're safe.
        except GeneratorExit:
            pass
        return

def tuplename(*names):
    '''Given a tuple as a name, return a single name joined by "_" characters.'''
    iterable = ("{:x}".format(abs(item)) if isinstance(item, internal.types.integer) else item for item in names)
    return '_'.join(iterable)

# copied mostly from the collections.namedtuple template
class namedtypedtuple(tuple):
    """
    A named tuple with actual type checking.
    """
    _fields = ()
    _types = ()

    def __new__(cls, *args):
        '''Construct a new instance of a tuple using the specified `args`.'''
        res = args[:]
        for n, t, x in zip(cls._fields, cls._types, args):
            if not isinstance(x, t):
                field_name = n.encode('utf8') if sys.version_info.major < 3 and isinstance(n, unicode) else n
                raise TypeError("Unexpected type ({!r}) for field {:s} should be {!r}.".format(type(x), field_name, t))
            continue
        return tuple.__new__(cls, res)

    @classmethod
    def _make(cls, iterable, cons=tuple.__new__, len=len):
        """Make a tuple using the values specified in `iterable`.

        If `cons` is specified as a callable, then use it to construct the type.
        If `len` is specified as a callable, then use it to return the length.
        """
        result = cons(cls, iterable)
        if len(result) != len(cls._fields):
            raise TypeError("Expected {:d} arguments, got {:d}.".format(len(cls._fields), len(result)))
        for n, t, x in zip(cls._fields, cls._types, result):
            if not isinstance(x, t):
                field_name = n.encode('utf8') if sys.version_info.major < 3 and isinstance(n, unicode) else n
                raise TypeError("Unexpected type ({!r} for field {:s} should be {!r}.".format(type(x), field_name, t))
            continue
        return result

    @classmethod
    def _type(cls, name):
        '''Return the type for the field `name`.'''
        res = (t for n, t in zip(cls._fields, cls._types) if n == name)
        try:
            result = builtins.next(res)
        except StopIteration:
            raise NameError("Unable to locate the type for an unknown field {!r}.".format(name))
        return result

    def __getattribute__(self, name):
        try:
            # honor the ._fields first
            fields = object.__getattribute__(self, '_fields')
            items = [item.lower() for item in fields]
            F = operator.itemgetter(items.index(name.lower()))
        except (IndexError, ValueError):
            F = lambda self: object.__getattribute__(self, name)
        return F(self)

    def __str__(self):
        cls, formats = self.__class__, itertools.chain(getattr(self, '_formats', []), len(self._fields) * ["{!s}".format])
        res = ("{!s}={!s}".format(internal.utils.string.escape(name, ''), format(value)) for name, value, format in zip(self._fields, self, formats))
        return "{:s}({:s})".format(cls.__name__, ', '.join(res))

    def __unicode__(self):
        cls, formats = self.__class__, itertools.chain(getattr(self, '_formats', []), len(self._fields) * ["{!s}".format])
        res = ("{!s}={!s}".format(internal.utils.string.escape(name, ''), format(value)) for name, value, format in zip(self._fields, self, formats))
        return u"{:s}({:s})".format(cls.__name__, ', '.join(res))

    def __repr__(self):
        return u"{!s}".format(self)

    def _replace(self, **fields):
        '''Assign the specified `fields` to the fields within the tuple.'''
        fc = fields.copy()
        result = self._make(map(fc.pop, self._fields, self))
        if fc:
            cls = self.__class__
            logging.warning(u"{:s}._replace({:s}) : Unable to assign unknown field names ({:s}) to tuple.".format('.'.join([__name__, cls.__name__]), internal.utils.string.kwargs(fields), '{' + ', '.join(map(internal.utils.string.repr, fc)) + '}'))
        return result
    def _asdict(self): return collections.OrderedDict(zip(self._fields, self))
    def __getnewargs__(self): return tuple(self)
    def __getstate__(self): return

class integerish(namedtypedtuple):
    """
    This is a namedtypedtuple that allows an implementor to treat it
    as an integer and perform various types of arithmetic upon it.

    The "_operand" attribute specifies which member of the tuple is
    used for performing any of the integral operations. The other
    members of the tuple are preserved. Unless one of them is None,
    which then means that the contents of that tuple are merged.
    """

    @property
    def _operands(self):
        '''This property is intended to be explicitly overwritten by the implementor.'''
        return builtins.tuple(*len(self._fields) * [internal.utils.fconstant])

    def __same__(self, other):
        '''Return true if `other` is the same type and can be used as an operand.'''
        raise NotImplementedError

    # XXX: hide the "__int__" attribute so that we can easily distinguish whether
    #      something is coercible using the "hasattr" builtin.

    #def __int__(self):
    #    raise NotImplementedError

    def __operator__(self, operation, other):
        cls, transform = self.__class__, [F(item) for F, item in zip(self._operands, self)]
        if isinstance(other, internal.types.integer):
            result = [Fitem(operation, other) for Fitem in transform]
        elif isinstance(other, self.__class__) and self.__same__(other):
            result = [item if Fitem(operation, item) is None else Fitem(operation, item) for Fitem, item in zip(transform, other)]
        elif any([hasattr(self, '__similar__') and self.__similar__(other), hasattr(other, '__similar__') and other.__similar__(self)]):
            result = [item if Fitem(operation, item) is None else Fitem(operation, item) for Fitem, item in zip(transform, other)]
        elif hasattr(other, '__int__'):
            logging.warning(u"{:s}.__operator__({!s}, {!r}) : Coercing the instance of type `{:s}` to an integer due to a dissimilarity with type `{:s}`.".format('.'.join([__name__, cls.__name__]), operation, other, other.__class__.__name__, cls.__name__))
            return self.__operator__(operation, int(other))
        else:
            raise TypeError(u"{:s}.__operator__({!s}, {!r}) : Unable to perform {:s} operation with type `{:s}` due to a dissimilarity with type `{:s}`.".format('.'.join([__name__, cls.__name__]), operation, other, operation.__name__, other.__class__.__name__, cls.__name__))
        return self.__class__(*result)

    def __operation__(self, operation):
        cls, transform = self.__class__, [F(item) for F, item in zip(self._operands, self)]
        iterable = (Fitem(operation) for Fitem in transform)
        result = [item if result is None else result for result, item in zip(iterable, self)]
        return self.__class__(*result)

    # general arithmetic
    def __add__(self, other):
        return self.__operator__(operator.add, other)
    def __sub__(self, other):
        return self.__operator__(operator.sub, other)
    def __and__(self, other):
        return self.__operator__(operator.and_, other)
    def __or__(self, other):
        return self.__operator__(operator.or_, other)
    def __xor__(self, other):
        return self.__operator__(operator.xor, other)
    def __lshift__(self, other):
        return self.__operator__(operator.lshift, other)
    def __rshift__(self, other):
        return self.__operator__(operator.rshift, other)

    # conversion expressions
    def __abs__(self):
        return self.__operation__(operator.abs)
    def __neg__(self):
        return self.__operation__(operator.neg)
    def __invert__(self):
        return self.__operation__(operator.invert)

    # methods that don't make sense...
    @classmethod
    def __mul__(cls, other):
        operation = operator.mul
        raise TypeError(u"{:s}.__mul__({!r}) : Refusing to perform nonsensical {:s} operation with type `{:s}`.".format('.'.join([__name__, cls.__name__]), other, operation.__name__, other.__class__.__name__))
    @classmethod
    def __div__(cls, other):
        operation = operator.div
        raise TypeError(u"{:s}.__div__({!r}) : Refusing to perform nonsensical {:s} operation with type `{:s}`.".format('.'.join([__name__, cls.__name__]), other, operation.__name__, other.__class__.__name__))
    @classmethod
    def __pow__(cls, other):
        operation = operator.pow
        raise TypeError(u"{:s}.__pow__({!r}) : Refusing to perform nonsensical {:s} operation with type `{:s}`.".format('.'.join([__name__, cls.__name__]), other, operation.__name__, other.__class__.__name__))
    @classmethod
    def __mod__(cls, other):
        operation = operator.mod
        raise TypeError(u"{:s}.__mod__({!r}) : Refusing to perform nonsensical {:s} operation with type `{:s}`.".format('.'.join([__name__, cls.__name__]), other, operation.__name__, other.__class__.__name__))
    @classmethod
    def __floordiv__(cls, other):
        operation = operator.floordiv
        raise TypeError(u"{:s}.__floordiv__({!r}) : Refusing to perform nonsensical {:s} operation with type `{:s}`.".format('.'.join([__name__, cls.__name__]), other, operation.__name__, other.__class__.__name__))
    @classmethod
    def __truediv__(cls, other):
        operation = operator.truediv
        raise TypeError(u"{:s}.__truediv__({!r}) : Refusing to perform nonsensical {:s} operation with type `{:s}`.".format('.'.join([__name__, cls.__name__]), other, operation.__name__, other.__class__.__name__))
    @classmethod
    def __divmod__(cls, other):
        operation = operator.divmod
        raise TypeError(u"{:s}.__divmod__({!r}) : Refusing to perform nonsensical {:s} operation with type `{:s}`.".format('.'.join([__name__, cls.__name__]), other, operation.__name__, other.__class__.__name__))

    # ...and finally opposites.
    __radd__ = __add__
    def __rsub__(self, other):
        this = operator.neg(self)
        return this.__operator__(operator.add, other)
    __rand__ = __and__
    __ror__ = __or__
    __rxor__ = __xor__

    # oh, but then there's nonsensical opposites too.
    @classmethod
    def __rlshift__(cls, other):
        operation = operator.lshift
        raise TypeError(u"{:s}.__rlshift__({!r}) : Refusing to perform nonsensical {:s} operation from type `{:s}`.".format('.'.join([__name__, cls.__name__]), other, operation.__name__, other.__class__.__name__))
    @classmethod
    def __rrshift__(cls, other):
        operation = operator.rshift
        raise TypeError(u"{:s}.__rrshift__({!r}) : Refusing to perform nonsensical {:s} operation from type `{:s}`.".format('.'.join([__name__, cls.__name__]), other, operation.__name__, other.__class__.__name__))

class symbol_t(object):
    """
    An object that is used to describe something that is symbolic in nature
    and has semantics that depend on symbolic values.

    This can be used to weakly describe an expression which allows for
    a user to then enumerate any symbolic parts.
    """
    def __hash__(self):
        cls, res = self.__class__, id(self)
        return hash((cls, res))

    @property
    def symbols(self):
        '''Must be implemented by each sub-class: Return a generator that returns each symbol described by `self`.'''
        raise internal.exceptions.MissingMethodError

class register_t(symbol_t):
    """
    An object representing a particular register as part of an architecture.
    This allows a user to determine the register's name, size, and allows
    for comparison to other registers.
    """

    def __hash__(self):
        identity = self.name if self.realname is None else self.realname
        items = identity, self.dtype, self.position, self.size
        return hash(items)

    @property
    def symbols(self):
        '''Yield the symbolic components that compose the register.'''
        # a register is technically a symbol, so we yield ourselves.
        yield self

    @property
    def id(self):
        '''Return the index of the register as ordered in IDA's list of registers.'''
        if isinstance(self.realname, internal.types.integer):
            return self.realname

        # otherwise we need to look in our register index for the name.
        res = idaapi.ph.regnames
        try:
            return res.index(self.realname or self.name)
        except ValueError:
            pass
        return -1

    @property
    def name(self):
        '''Return the name of the register.'''
        return self.__name__
    @property
    def dtype(self):
        '''Return the IDA dtype of the register.'''
        return self.__dtype__
    @property
    def bits(self):
        '''Return the size of the register in bits.'''
        return self.__size__
    @property
    def size(self):
        '''Return the size of the register in bytes.'''
        res = math.ceil(self.__size__ / 8)
        return math.trunc(res)
    @property
    def position(self):
        '''Return the binary offset of the current register into its full register that contains it.'''
        return self.__position__
    @property
    def type(self):
        '''Return the pythonic type of the register.'''
        return self.__ptype__, self.__size__ // 8

    def __format__(self, spec):
        '''Return the architecture's register prefix concatenated to the register's name.'''
        if spec != 's':
            cls = self.__class__
            raise TypeError("unsupported format string ({!s}) passed to {:s}".format(spec, '.'.join([cls.__name__, '__format__'])))
        prefix = getattr(self.architecture, 'prefix', '') if hasattr(self, 'architecture') else ''
        return prefix + self.name

    def __str__(self):
        '''Return the architecture's register prefix concatenated to the register's name.'''
        prefix = getattr(self.architecture, 'prefix', '') if hasattr(self, 'architecture') else ''
        return prefix + self.name

    def __repr__(self):
        iterable = (name for name in dir(idaapi) if name.startswith('dt_') and getattr(idaapi, name) == self.dtype)
        try:
            dt = next(iterable)
        except StopIteration:
            dt = 'unknown'
        cls = register_t
        return "<class '{:s}' index={:d} dtype={:s} name='{!s}' position={:d}{:+d}>".format(cls.__name__, self.id, dt, internal.utils.string.escape(self.name, '\''), self.position, self.bits)

    def __eq__(self, other):
        if isinstance(other, internal.types.string):
            return self.name.lower() == other.lower()
        elif isinstance(other, register_t):
            return self is other
        elif hasattr(other, '__eq__'):  # XXX: i fucking hate python
            return other.__eq__(self)
        return other is self

    def __ne__(self, other):
        return not (self == other)

    def __contains__(self, other):
        '''Return true if the `other` register is any of the components of the current register.'''
        viewvalues = {item for item in self.__children__.values()}
        return other in viewvalues

    def subset(self, other):
        '''Return true if the `other` register is a component of the current register.'''
        def collect(node):
            res = {node}
            [res.update(collect(item)) for item in node.__children__.values()]
            return res
        return other in self.alias or other in collect(self)

    def superset(self, other):
        '''Return true if the `other` register uses the current register as a component.'''
        res, pos = {item for item in []}, self
        while pos is not None:
            res.add(pos)
            pos = pos.__parent__
        return other in self.alias or other in res

    def related(self, other):
        '''Return true if the `other` register may overlap with the current one and thus might be affected when one is modified.'''
        return self.superset(other) or self.subset(other)

    def __int__(self):
        '''Return the integer value of the current register.'''
        rv, rname = idaapi.regval_t(), self.name
        if not idaapi.get_reg_val(rname, rv):
            raise internal.exceptions.DisassemblerError(u"{!s} : Unable to fetch the integer value from the associated register name ({:s}).".format(self, rname))
        mask = pow(2, self.bits) - 1
        if rv.rvtype == idaapi.RVT_INT:
            return rv.ival & mask
        elif rv.rvtype == idaapi.RVT_FLOAT:
            logging.warning(u"{!s} : Converting a non-integer register type ({:d}) to an integer using {:d} bytes.".format(self, rv.rvtype, self.size))
            bytes = rv.fval.bytes
        else:
            logging.warning(u"{!s} : Converting a non-integer register type ({:d}) to an integer using {:d} bytes.".format(self, rv.rvtype, self.size))
            bytes = rv.bytes()
        return functools.reduce(lambda agg, item: agg * 0x100 + item, bytearray(bytes), 0)

    def __float__(self):
        '''Return the floating-point value of the current register.'''
        rv, rname = idaapi.regval_t(), self.name
        if not idaapi.get_reg_val(rname, rv):
            raise internal.exceptions.DisassemblerError(u"{!s} : Unable to fetch the floating-point value from the associated register name ({:s}).".format(self, rname))
        if rv.rvtype == idaapi.RVT_FLOAT:
            return rv.fval._get_float()
        raise internal.exceptions.InvalidTypeOrValueError(u"{!s} : Unable to concretize an unknown register value type ({:d}) to a floating-point number.".format(self, rv.rvtype))

    @property
    def bytes(self):
        '''Return the bytes that make up the value of the current register.'''
        rv, rname = idaapi.regval_t(), self.name
        if not idaapi.get_reg_val(rname, rv):
            raise internal.exceptions.DisassemblerError(u"{!s} : Unable to fetch the bytes for the associated register name ({:s}).".format(self, rname))
        return rv.bytes()

    def __reduce__(self):
        return '.'.join(['architecture', 'register', self.__name__.replace('.', '_')])

class instruction(object):
    """
    This namespace provides some basic utilities to extract an instruction
    from the database. Some other utilities are provided to interact with
    the operands for an instruction as we all counting them.
    """
    @classmethod
    def at(cls, ea):
        '''Disassemble the address `ea` and return the ``idaapi.insn_t`` that is associated with it.'''
        ea = int(ea)

        # If we're using backwards-compatiblity mode (which means decode_insn takes
        # different parameters, then manage the result using idaapi.cmd
        if hasattr(idaapi, 'cmd'):
            length = idaapi.decode_insn(ea)
            if idaapi.__version__ < 7.0:
                return idaapi.cmd.copy()

            tmp = idaapi.insn_t()
            tmp.assign(idaapi.cmd)
            return tmp

        # Otherwise we can just use the API as we see fit
        res = idaapi.insn_t()
        length = idaapi.decode_insn(res, ea)
        return res

    @classmethod
    def mnemonic(cls, ea):
        '''Return the mnemonic of the instruction that is at the address `ea`.'''
        res = (idaapi.ua_mnem(int(ea)) or '').lower()
        return internal.utils.string.of(res)

    @classmethod
    def feature(cls, ea):
        '''Return the feature bitmask for the instruction at the address `ea`.'''
        insn = cls.at(ea)
        res = insn.get_canon_feature()
        return idaapi.as_uint32(res)

    @classmethod
    def count(cls, ea):
        '''Returns the number of available operands for the instruction at the address `ea`.'''
        insn = cls.at(ea)
        operands = insn.Operands if hasattr(idaapi, 'cmd') else [insn.ops[index] for index in builtins.range(idaapi.UA_MAXOP)]
        iterable = itertools.takewhile(internal.utils.fcompose(operator.attrgetter('type'), functools.partial(operator.ne, idaapi.o_void)), operands)
        return sum(1 for operand in iterable)

    uses_bits = [getattr(idaapi, "CF_USE{:d}".format(1 + idx)) if hasattr(idaapi, "CF_USE{:d}".format(1 + idx)) else pow(2, bit) for bit, idx in zip(itertools.chain(builtins.range(8, 8 + 6), builtins.range(19, 19 + 2)), builtins.range(idaapi.UA_MAXOP))]
    @classmethod
    def uses_operand(cls, ea, opnum):
        '''Return whether the instruction at address `ea` uses the operand `opnum` without changing it.'''
        feature = cls.feature(ea)
        return True if feature & cls.uses_bits[opnum] else False

    @classmethod
    def uses(cls, ea):
        '''Return the index of each operand that is used by the instruction at the address `ea` but not changed.'''
        feature = cls.feature(ea)
        return [index for index, cf in enumerate(cls.uses_bits) if feature & cf]

    changes_bits = [getattr(idaapi, "CF_CHG{:d}".format(1 + idx)) if hasattr(idaapi, "CF_CHG{:d}".format(1 + idx)) else pow(2, bit) for bit, idx in zip(itertools.chain(builtins.range(2, 2 + 6), builtins.range(17, 17 + 2)), builtins.range(idaapi.UA_MAXOP))]
    @classmethod
    def changes_operand(cls, ea, opnum):
        '''Return whether the instruction at address `ea` changes the operand `opnum`.'''
        feature = cls.feature(ea)
        return feature & cls.changes_bits[opnum]

    @classmethod
    def changes(cls, ea):
        '''Return the index of each operand that is changed by the instruction at the address `ea`.'''
        feature = cls.feature(ea)
        return [index for index, cf in enumerate(cls.changes_bits) if feature & cf]

    @classmethod
    def operands(cls, ea):
        '''Returns all of the ``idaapi.op_t`` instances for the instruction at the address `ea`.'''
        insn = cls.at(ea)

        # if we're in compatibility mode, then old-fashioned IDA requires us to copy
        # our operands into our new types.
        if hasattr(idaapi, 'cmd'):

            # take operands until we encounter an idaapi.o_void
            iterable = itertools.takewhile(internal.utils.fcompose(operator.attrgetter('type'), functools.partial(operator.ne, idaapi.o_void)), insn.Operands)

            # if we're using IDA < 7.0, then make copies of each instruction and return it
            if idaapi.__version__ < 7.0:
                return [op.copy() for op in iterable]

            # otherwise, we need to make an instance of it and then assign to make a copy
            iterable = ((idaapi.op_t(), op) for op in iterable)
            return [[n.assign(op), n][1] for n, op in iterable]

        # apparently idaapi is not increasing a reference count for our operands, so we
        # need to make a copy of them quickly before we access them.
        operands = [idaapi.op_t() for index in builtins.range(idaapi.UA_MAXOP)]
        [ op.assign(insn.ops[index]) for index, op in enumerate(operands)]

        # now we can just fetch them until idaapi.o_void and return it as a list.
        iterable = itertools.takewhile(internal.utils.fcompose(operator.attrgetter('type'), functools.partial(operator.ne, idaapi.o_void)), operands)
        return [op for op in iterable]

    @classmethod
    def operand(cls, ea, opnum):
        '''Returns the ``idaapi.op_t`` for the operand `opnum` belonging to the instruction at the address `ea`.'''
        insn = cls.at(ea)

        # If we're using backwards-compatiblity mode then we need to assign the
        # operand into our op_t.
        if hasattr(idaapi, 'cmd'):
            # IDA < 7.0 means we can just call .copy() to duplicate it
            if idaapi.__version__ < 7.0:
                return insn.Operands[opnum].copy()

            # Otherwise we'll need to instantiate it, and then .assign() into it
            res = idaapi.op_t()
            res.assign(insn.Operands[opnum])
            return res

        # Otherwise we need to make a copy of it because IDA will crash if we don't
        res = idaapi.op_t()
        res.assign(insn.ops[opnum])
        return res

    @classmethod
    def access(cls, ea):
        '''Yield the ``opref_t`` for each operand belonging to the instruction at the address `ea`.'''
        ea, fn, insn = int(ea), idaapi.get_func(int(ea)), cls.at(int(ea))

        # Just some basic utilities for getting the features of the instruction and the flags of the address.
        features, flags = cls.feature(ea), address.flags(ea)
        Ffeature, Fflag = map(functools.partial(functools.partial, operator.and_), [features, flags])

        # Get all the instruction-specific attributes that are relevant to the access_t of each operand.
        is_call, is_jump, is_shift = cls.is_call(ea), cls.is_branch(ea), cls.is_shift(ea)
        operands, MS_XTYPE = cls.operands(ea), Fflag(idaapi.MS_0TYPE | idaapi.MS_1TYPE)

        # Now because we have no way to determine conditional branches, we need to enumerate the references
        # from this instruction. Not all of them, though, just any that are code references and not idaapi.fl_F.
        has_code_references = next((True for _, xiscode, xrtype in xref.of(ea) if xiscode and xrtype != idaapi.fl_F), False)

        # Assign the base access types that we'll choose from using the operand type and whether the
        # operand is being read from or written to. These get modified depending on other characteristics.
        if is_call:
            xrefcode, xreftype, xrefdefault = True, {
                idaapi.o_near: [idaapi.fl_CN, idaapi.fl_U],
                idaapi.o_far: [idaapi.fl_CF, idaapi.fl_U],
                idaapi.o_mem: [idaapi.dr_R, idaapi.fl_U],
                idaapi.o_displ: [idaapi.dr_R, idaapi.fl_U],
            }, [idaapi.fl_F, idaapi.fl_F]

        # Then we'll do the jump instructions which is pretty much the same other than a different reftype.
        elif is_jump or has_code_references:
            xrefcode, xreftype, xrefdefault = True, {
                idaapi.o_near: [idaapi.fl_JN, idaapi.fl_JN],
                idaapi.o_far: [idaapi.fl_JF, idaapi.fl_JF],
                idaapi.o_mem: [idaapi.dr_R, idaapi.dr_W],
                idaapi.o_displ: [idaapi.dr_R, idaapi.dr_W],
            }, [idaapi.fl_F, idaapi.fl_F]

        # Anything else is just a regular instruction which can either read or write to its operand.
        else:
            xrefcode, xreftype, xrefdefault = False, {
                idaapi.o_imm: [idaapi.fl_USobsolete, idaapi.dr_U],
            }, [idaapi.dr_R, idaapi.dr_W]

        # Iterate through all of the operands and yield their access_t.
        for opnum, op in enumerate(operands):
            used, modified = Ffeature(cls.uses_bits[opnum]), Ffeature(cls.changes_bits[opnum])
            ri, has_xrefs = address.refinfo(ea, opnum), idaapi.op_adds_xrefs(flags, opnum)

            # If the operand is not used or modified, then our access_t is empty. We can use
            # the USobsolete flag here since it's used-specified..but deprecated.
            if not (used or modified):
                yield opref_t(ea, opnum, access_t(idaapi.fl_USobsolete, xrefcode))
                continue

            # Now we need to figure out the base type which comes from the operand type, the
            # used/modified flag, and whether the instruction is a branch instruction or not.
            read, write = (access_t(item, xrefcode) for item in xreftype.get(op.type, xrefdefault))
            access = write | read if used and modified else write if modified else read

            # We now need to figure out how we're supposed to modify the access_t. If it's a
            # branch and the operand references memory, then we include 'r' to represent a load.
            if xrefcode:
                access = access | 'x'
                access = access | 'r' if op.type in {idaapi.o_mem, idaapi.o_displ} else access

            # If it's data and it references memory, then we need to update the access with '&'.
            elif op.type in {idaapi.o_imm} and has_xrefs:
                access = access | '&'
            yield opref_t(ea, opnum, access)
        return

    @classmethod
    def reference(cls, ea, opnum, refinfo=None):
        '''Return the address being referenced for operand `opnum` at instruction address `ea` using the specified `refinfo` if it is available.'''
        get_dtype_attribute = operator.attrgetter('dtyp' if idaapi.__version__ < 7.0 else 'dtype')
        get_dtype_size = idaapi.get_dtyp_size if idaapi.__version__ < 7.0 else idaapi.get_dtype_size

        # Grab the instruction, the operands, and then the operand. This way we can extract
        # the operand value and its size so that we can turn it into an adiff_t.
        ea, insn, operand = int(ea), instruction.at(ea), instruction.operand(ea, opnum)
        dtype, inverted, negated = get_dtype_attribute(operand), node.alt_opinverted(insn.ea, operand.n), node.alt_opnegated(insn.ea, operand.n)
        value, bits = operand.value if operand.type in {idaapi.o_imm} else operand.addr, 8 * get_dtype_size(dtype)
        avalue = idaapi.as_signed(value, bits)

        # If we were given a refinfo_t then we can use it to calculate exactly what
        # address is being referenced by the operand and return it.
        if refinfo:
            target, base = idaapi.ea_pointer(), idaapi.ea_pointer()

            # Try and calculate the reference for the operand value. If we couldn't, then we simply treat the value as-is.
            if not idaapi.calc_reference_data(target.cast(), base.cast(), insn.ea, refinfo, avalue):
                logging.debug(u"{:s}.reference({:#x}, {:d}) : The disassembler could not calculate the target for the reference ({:d}) at address {:#x}.".format('.'.join([__name__, cls.__name__]), ea, opnum, refinfo.flags & idaapi.REFINFO_TYPE, insn.ea))
                return value
            return target.value()

            # XXX: This is an attempt to manually calculate this, but I think I'm supposed
            #      to clamp the operand value to the size of the reference type and I also
            #      have no idea how REFINFO_SIGNEDOP is supposed to work with it.
            Ftranslate = functools.partial(operator.sub if refinfo.flags & idaapi.REFINFO_SUBTRACT else operator.add, refinfo.base)
            return Ftranslate(avalue if refinfo.flags & idaapi.REFINFO_SIGNEDOP else avalue)

        # Otherwise, we need to figure out the refinfo_t from the default. So, unless the
        # user changed the default, this should always result in returning the immediate.
        refinfo = idaapi.refinfo_t()
        refinfo.set_type(idaapi.get_default_reftype(insn.ea))
        refinfo.base, refinfo.target = 0, idaapi.BADADDR
        if operand.type not in {idaapi.o_mem, idaapi.o_near, idaapi.o_far, idaapi.o_imm}:
            raise internal.exceptions.InvalidTypeOrValueError(u"{:s}.reference({:#x}, {:d}) : Unable to determine the reference type for the instruction at address {:#x} due to its operand ({:d}) being an unsupported type ({:d}).".format('.'.join([__name__, cls.__name__]), ea, opnum, insn.ea, opnum, operand.type))

        # If the target base can't be calculated, then we need to treat it as a regular
        # operand by checking if it's signed or negated and returning the correct value.
        target, maximum = idaapi.calc_target(insn.ea, avalue, refinfo), pow(2, bits)
        signed, unsigned = (value - maximum, value) if avalue > 0 else (avalue, value & (maximum - 1))
        result = signed if inverted else unsigned
        return target if target != idaapi.BADADDR else result if operand.type == idaapi.o_imm else value

    @classmethod
    def is_sentinel(cls, ea):
        '''Return whether the instruction at the address `ea` is a sentinel instruction that does not execute the instruction that immediately follows it.'''
        ok = address.flags(ea, idaapi.MS_CLS) == idaapi.FF_CODE and cls.feature(ea) & idaapi.CF_STOP
        return True if ok else False

    @classmethod
    def is_shift(cls, ea):
        '''Return whether the instruction at the address `ea` is a shift instruction.'''
        ok = address.flags(ea, idaapi.MS_CLS) == idaapi.FF_CODE and cls.feature(ea) & idaapi.CF_SHFT
        return True if ok else False

    @classmethod
    def is_branch(cls, ea):
        '''Return whether the instruction at the address `ea` is a branch instruction.'''
        xiterable = (True for _, xiscode, xrtype in xref.of(ea) if xiscode and xrtype != idaapi.fl_F)
        target, bbargs = (ea, []) if idaapi.__version__ < 7.0 else (cls.at(ea), [False])
        either = idaapi.is_indirect_jump_insn(target) or next(xiterable, False)
        return idaapi.is_basic_block_end(target, *bbargs) and not idaapi.is_call_insn(target) and either

    @classmethod
    def is_call(cls, ea):
        '''Return whether the instruction at the address `ea` is a call (direct or indirect) instruction.'''
        feature, target = cls.feature(ea), ea if idaapi.__version__ < 7.0 else cls.at(ea)
        ok = idaapi.is_call_insn(target) if hasattr(idaapi, 'is_call_insn') else address.flags(ea, idaapi.MS_CLS) == idaapi.FF_CODE and feature & idaapi.CF_CALL
        return True if ok else False

    @classmethod
    def is_calli(cls, ea):
        '''Return whether the instruction at the address `ea` is a call (indirect) instruction.'''
        feature, target = cls.feature(ea), ea if idaapi.__version__ < 7.0 else cls.at(ea)
        ok = idaapi.is_call_insn(target) if hasattr(idaapi, 'is_call_insn') else address.flags(ea, idaapi.MS_CLS) == idaapi.FF_CODE and feature & idaapi.CF_CALL
        return True if ok and feature & idaapi.CF_JUMP else False

    @classmethod
    def is_return(cls, ea):
        '''Return whether the instruction at the address `ea` is a return instruction.'''
        target = ea if idaapi.__version__ < 7.0 else cls.at(ea)
        return True if idaapi.is_ret_insn(target) else False

    @classmethod
    def is_indirect(cls, ea):
        '''Return whether the instruction at the address `ea` is an unconditional (indirect) branch instruction.'''
        target, bbargs = (ea, []) if idaapi.__version__ < 7.0 else (cls.at(ea), [False])
        if hasattr(idaapi, 'is_indirect_jump_insn'):
            return True if idaapi.is_indirect_jump_insn(target) else False
        features, invalid, expected = cls.feature(ea), any([idaapi.is_call_insn(target), idaapi.is_ret_insn(target)]), idaapi.CF_STOP | idaapi.CF_JUMP
        ok = idaapi.is_basic_block_end(target, *bbargs) and not invalid and features & expected == expected
        return True if ok else False

    @classmethod
    def is_unconditional(cls, ea):
        '''Return whether the instruction at the address `ea` is an unconditional (direct and indirect) branch instruction.'''
        features, expected = cls.feature(ea), idaapi.CF_STOP | idaapi.CF_HLL
        target, bbargs = (ea, []) if idaapi.__version__ < 7.0 else (cls.at(ea), [False])
        ok = idaapi.is_basic_block_end(target, *bbargs) and not idaapi.is_ret_insn(target) and features & expected == expected
        return True if ok else False

    @classmethod
    def is_conditional(cls, ea):
        '''Return whether the instruction at the address `ea` is an conditional branch instruction.'''
        target, bbargs = (ea, []) if idaapi.__version__ < 7.0 else (cls.at(ea), [False])
        feature, invalid = cls.feature(ea), any([idaapi.is_call_insn(target), idaapi.is_ret_insn(target)])
        xiterable = (True for _, xiscode, xrtype in xref.of(ea) if xiscode and xrtype != idaapi.fl_F)
        ok = idaapi.is_basic_block_end(target, *bbargs) and not invalid and not feature & idaapi.CF_STOP and next(xiterable, False)
        return True if ok else False

class regmatch(object):
    """
    This namespace is used to assist with doing register matching
    against instructions. This simplifies the interface for register
    matching so that one can specify whether any number of registers
    are written to or read from.
    """
    def __new__(cls, *registers, **modifiers):
        '''Construct a closure that can be used for matching instruction using the specified `registers` and `modifiers`.'''
        if not registers:
            args = ', '.join(map(internal.utils.string.escape, registers))
            mods = internal.utils.string.kwargs(modifiers)
            raise internal.exceptions.InvalidParameterError(u"{:s}({:s}{:s}) : The specified registers are empty.".format('.'.join([__name__, cls.__name__]), args, (', '+mods) if mods else ''))
        use, iterops = cls.use(registers), cls.modifier(**modifiers)
        def match(ea):
            return any(map(functools.partial(use, ea), iterops(ea)))
        return match

    @classmethod
    def use(cls, registers):
        '''Return a closure that checks if an address and opnum uses either of the specified `registers`.'''
        import __catalog__ as catalog

        # convert any regs that are strings into their correct object type
        regs = { architecture.by_name(r) if isinstance(r, internal.types.string) else r for r in registers }

        # returns an iterable of bools that returns whether r is a subset of any of the registers in `regs`.
        match = lambda r, regs=regs: any(map(r.related, regs))

        # returns true if the operand at the specified address is related to one of the registers in `regs`.
        def uses_register(ea, opnum):
            insn, operand = instruction.at(ea), instruction.operand(ea, opnum)
            val = catalog.operand.decode(insn, operand)
            if isinstance(val, symbol_t):
                return any(map(match, val.symbols))
            return False

        return uses_register

    @classmethod
    def modifier(cls, **modifiers):
        '''Return a closure that iterates through all the operands in an address that use either of the specified `modifiers`.'''
        ops_count = internal.utils.fcompose(instruction.operands, tuple, len)

        # by default, grab all operand indexes
        iterops = internal.utils.fcompose(ops_count, builtins.range, sorted)

        # now we can collect our required conditions to yield an operand index.
        conditions = []

        # if `read` is specified, then only grab operand indexes that are read from
        read_args = ['read', 'r']
        if any(item in modifiers for item in read_args):
            read = next(modifiers[item] for item in read_args if item in modifiers)
            Fread = (lambda ref: 'r' in ref.access) if read else (lambda ref: 'r' not in ref.access)
            conditions.append(Fread)

        # if `write` is specified that only grab operand indexes that are written to
        write_args = ['written', 'write', 'w']
        if any(item in modifiers for item in write_args):
            write = next(modifiers[item] for item in write_args if item in modifiers)
            Fwrite = (lambda ref: 'w' in ref.access) if write else (lambda ref: 'w' not in ref.access)
            conditions.append(Fwrite)

        # if `execute` is specified that only grab operand indexes that are executed
        execute_args = ['executed', 'execute', 'exec', 'x']
        if any(item in modifiers for item in execute_args):
            execute = next(modifiers[item] for item in execute_args if item in modifiers)
            Fexec = (lambda ref: 'x' in ref.access) if execute else (lambda ref: 'x' not in ref.access)
            conditions.append(Fexec)

        # if `readwrite` is specified that only grab operand indexes that are modified
        readwrite_args = ['modify', 'modified', 'changed', 'readwrite', 'rw']
        if any(item in modifiers for item in readwrite_args):
            write = next(modifiers[item] for item in readwrite_args if item in modifiers)
            Fwrite = (lambda ref: 'rw' in ref.access) if write else (lambda ref: 'rw' not in ref.access)
            conditions.append(Fwrite)

        # if `readexecute` is specified that only grab operand indexes that are loaded before being used to execute
        execute_args = ['readexecute', 'readexec', 'rx']
        if any(item in modifiers for item in execute_args):
            execute = next(modifiers[item] for item in execute_args if item in modifiers)
            Fexec = (lambda ref: 'rx' in ref.access) if execute else (lambda ref: 'rx' not in ref.access)
            conditions.append(Fexec)

        # now we just need to stack our conditions and enumerate the operands while only yielding their index.
        Fconditions = internal.utils.fcompose(internal.utils.fthrough(*conditions), any) if conditions else internal.utils.fconstant(True)
        return internal.utils.fcompose(instruction.access, functools.partial(internal.utils.ifilter, Fconditions), functools.partial(internal.utils.imap, operator.attrgetter('opnum')), sorted)

## figure out the boundaries of sval_t
if idaapi.BADADDR == 0xffffffff:
    sval_t = ctypes.c_long
elif idaapi.BADADDR == 0xffffffffffffffff:
    sval_t = ctypes.c_longlong
else:
    sval_t = ctypes.c_int
    logging.fatal(u"{:s} : Unable to determine size of idaapi.BADADDR in order to determine boundaries of sval_t. Setting default size to {:d}-bits. The value of idaapi.BADADDR is {!r}.".format(__name__, ctypes.sizeof(sval_t), idaapi.BADADDR))

#Ref_Types = {
#    0 : 'Data_Unknown', 1 : 'Data_Offset',
#    2 : 'Data_Write', 3 : 'Data_Read', 4 : 'Data_Text',
#    5  : 'Data_Informational',
#    16 : 'Code_Far_Call', 17 : 'Code_Near_Call',
#    18 : 'Code_Far_Jump', 19 : 'Code_Near_Jump',
#    20 : 'Code_User', 21 : 'Ordinary_Flow'
#}
class reftype_t(object):
    """
    An object representing a reference type that allows one to easily extract
    semantics using membership operators. This type uses more familiar "rwx"
    that is most commonly associated with posix file permissions in order to
    simplify the semantics of the numerous available reference types.

    When testing membership, "r" means read, "w" means write, "x" means execute,
    and "&" means reference. The intention of this is to make it easier for one
    to verify whether a reference is reading, writing, or executing something.
    """

    if idaapi.__version__ < 7.0:
        __mapper__ = {
            0 : '',
            1 : '&r',
            2 : 'w', 3 : 'r'
        }
    else:
        __mapper__ = {
            idaapi.fl_CF : 'rx', idaapi.fl_CN : 'rx',   # call far, call near
            idaapi.fl_JF : 'rx', idaapi.fl_JN : 'rx',   # jmp far, jmp near
            idaapi.fl_F : 'rx',                         # single-step
            idaapi.dr_O : '&r', idaapi.dr_I : '&r',     # offset, implicit
            idaapi.dr_R : 'r', idaapi.dr_W : 'w',       # read, right
            getattr(idaapi, 'fl_U', 0) : '',
        }
    __mapper__[31] = '*'        # code 31 used internally by ida-minsc

    def __operator__(self, F, item):
        cls = self.__class__
        if isinstance(item, cls):
            res = F(self.S, item.S)
        elif isinstance(item, internal.types.integer):
            res = F(self.S, cls.of(item))
        else:
            res = F(self.S, item)
        return cls.of_action(str().join(res)) if isinstance(res, internal.types.unordered) else res

    def __hash__(self):
        return hash(self.F)
    def __or__(self, other):
        return self.__operator__(operator.or_, {item for item in other})
    def __and__(self, other):
        return self.__operator__(operator.and_, {item for item in other})
    def __xor__(self, other):
        return self.__operator__(operator.xor, {item for item in other})
    def __sub__(self, other):
        return self.__operator__(operator.sub, {item for item in other})

    def __int__(self):
        return idaapi.XREF_MASK & self.F
    def __cmp__(self, other):
        return cmp(*map(int, self))
    def __eq__(self, other):
        if isinstance(other, self.__class__):
            return operator.eq(*map(int, [self, other]))
        return self.__operator__(operator.eq, {item for item in other})
    def __ne__(self, other):
        if isinstance(other, self.__class__):
            return operator.ne(*map(int, [self, other]))
        return self.__operator__(operator.ne, {item for item in other})
    def __lt__(self, other):
        return operator.lt(*map(int, [self, other]))
    def __ge__(self, other):
        return operator.ge(*map(int, [self, other]))
    def __gt__(self, other):
        return operator.gt(*map(int, [self, other]))

    def __contains__(self, type):
        if isinstance(type, internal.types.integer):
            res = self.F & type
        else:
            res = operator.contains(self.S, type.lower())
        return True if res else False
    def __getitem__(self, type):
        if isinstance(type, internal.types.integer):
            res = self.F & type
        else:
            res = operator.contains(self.S, type.lower())
        return True if res else False

    def __iter__(self):
        for item in sorted(self.S):
            yield item
        return

    def __repr__(self):
        return "reftype_t({:s})".format(str().join(sorted(self.S)))

    def __init__(self, xrtype, iterable):
        '''Construct a ``reftype_t`` using `xrtype` and any semantics specified in `iterable`.'''
        self.F = xrtype
        self.S = { item for item in iterable }

    @classmethod
    def of_type(cls, xrtype):
        '''Convert an IDA reference type in `xrtype` to a ``reftype_t``.'''
        if not isinstance(xrtype, internal.types.integer):
            raise internal.exceptions.InvalidTypeOrValueError(u"{:s}.of_type({!r}) : Refusing the coercion of a non-integral {!s} into the required type ({!s}).".format('.'.join([__name__, cls.__name__]), xrtype, xrtype.__class__, 'xrtype'))
        items = cls.__mapper__.get(xrtype, '')
        iterable = (item for item in items)
        return cls(xrtype, iterable)

    @staticmethod
    def of(xrtype):
        '''Convert an IDA reference type in `xrtype` to an ``access_t``.'''
        return access_t(xrtype)

    @classmethod
    def of_action(cls, state):
        '''Convert a ``reftype_t`` in `state` back into an IDA reference type.'''
        if state == '*':
            return cls(31, '*')     # code 31 used internally by ida-minsc
        elif state == 'rw':
            state = 'w'

        # Verify that the state we were given can be iterated through.
        try:
            (item for item in state)

        except TypeError:
            raise internal.exceptions.InvalidTypeOrValueError(u"{:s}.of_action({!r}) : Unable to coerce the requested state ({!r}) into a valid cross-reference type ({!s}).".format('.'.join([__name__, cls.__name__]), state, state, cls.__name__))

        # Search through our mapper for the correct contents of the reftype_t.
        res = { item for item in state }
        for F, t in cls.__mapper__.items():
            if { item for item in t } == res:
                return cls(F, res)
            continue
        resP = str().join(sorted(res))
        raise internal.exceptions.InvalidTypeOrValueError(u"{:s}.of_action({!r}) : Unable to to coerce the requested state ({!r}) into a valid cross-reference type ({!s}).".format('.'.join([__name__, cls.__name__]), resP, resP, cls.__name__))

    @staticmethod
    def of_action(state):
        '''Convert a ``reftype_t`` in `state` back into an IDA reference type.'''
        if '&' in state:
            xrtype = idaapi.dr_I
        elif 'w' in state:
            xrtype = idaapi.dr_W
        elif 'r' in state:
            xrtype = idaapi.dr_R
        return access_t(xrtype, 1)

class access_t(object):
    """
    This class represents the type of access for a given reference and
    aims to simplify discovering the semantics of the access using membership
    operators. To meet this need, the class uses the more familiar "rwx"
    syntax that is commonly associated with posix file permissions. There
    are two additional characters that have been added to this which are
    the "&" character representing that the access is an indirect reference
    and "?" which represents an unsupported or unknown access type.

    Object instantiated form this class are mergable with each other in order
    to allow combining the accesses from two completely different reference
    types but still retain their original meaning after merge. There are two
    classes of references which are either code or data and these are kept
    track of by this class in order to determine how it may be modified.

    When comparing instances of these class, the original reference type
    is maintained. Thus when comparing its equality with another instance
    of the same class, it is only the type that is compared. Every other
    set operation will interact with the flags of the particular class.
    """
    __xrflags__ = {8: '&', 4: 'r', 2: 'w', 1: 'x'}
    __xrflags__[16] = '?'

    # This is the table containing the flags for each of the xrtypes. If
    # we're asked to merge with another xrtype, we should only have to
    # set the required bits and do nothing more.
    __xrtable__ = {
        idaapi.fl_F : 1,    # single-step

        # call far, call near
        idaapi.fl_CF : 1, idaapi.fl_CN : 1,

        # jmp far, jmp near
        idaapi.fl_JF : 1, idaapi.fl_JN : 1,

        # offset, implicit
        idaapi.dr_O : 8, idaapi.dr_I : 8,

        # read, write
        idaapi.dr_R : 4, idaapi.dr_W : 2,

        # neither, using a deprecated (obsolete) flag from IDA. this is used as a
        # backdoor to disable enforcing flags based on the xref type (code or data).
        idaapi.fl_USobsolete : 0,

        # any unknowns that we know about set the highest bit so that we can track it
        # through the references. both fl_U and dr_U are the same values, but whatev.
        getattr(idaapi, 'fl_U', 0) : 0x10, getattr(idaapi, 'dr_U', 0) : 0x10,

        # this bit is unused, but we keep it for compatibility since it was used in older
        # versions of this plugin to represent not-yet-determined reference types.
        31 : 0x10
    }
    __xftypes__ = {idaapi.fl_F, idaapi.fl_CF, idaapi.fl_CN, idaapi.fl_JF, idaapi.fl_JN}
    __unktypes__ = {idaapi.fl_USobsolete, getattr(idaapi, 'fl_U', 0), getattr(idaapi, 'dr_U', 0), 31}

    def __init__(self, xrtype, iscode=False):
        '''Create a new ``access_t`` from the flags specified by `xrtype` and the boolean `iscode`.'''
        XREF_MASK = getattr(idaapi, 'XREF_MASK', 0x1f)
        self.__xrtype = xrtype
        self.__xrcode = True if iscode else False
        self.__xrflag = self.__xrtable__.get(xrtype & XREF_MASK, 0)

    # If we're code, then 'x' (1) will always be set.
    # If we're not code and neither '&' (8), 'r' (4), or 'w' (2) is set, it's actually '&' (8).
    # If the reftype is the fl_USobsolete backdoor, then we ignore all enforcement.
    @classmethod
    def __adjust_flags__(cls, xrtype, iscode, flag):
        ignore_mask, required_set = (14, 8) if not iscode else (0, 1) if xrtype in cls.__xftypes__ else (0, 0)
        return flag if flag & ignore_mask else flag if xrtype in cls.__unktypes__ else flag | required_set

    def __iter__(self):
        flag = self.__adjust_flags__(self.__xrtype, self.__xrcode, self.__xrflag)
        bits = {bit for bit in self.__xrflags__ if flag & bit}
        return (self.__xrflags__[bit] for bit in reversed(sorted(bits)))

    def __get_flags__(self):
        flag = self.__adjust_flags__(self.__xrtype, self.__xrcode, self.__xrflag)
        iterable = (bit for bit in self.__xrflags__ if flag & bit)
        return functools.reduce(operator.or_, iterable)

    def __get_type__(self):
        return self.__xrtype, self.__xrcode

    def __merge_flags__(self, flags):
        self.__xrflag |= flags & 0xf
        return self

    def __format__(self, spec):
        xr, flag = self.__xrtype, self.__adjust_flags__(self.__xrtype, self.__xrcode, self.__xrflag)

        if spec == 's':
            bits = {bit for bit in self.__xrflags__ if flag & bit}
            iterable = (self.__xrflags__[bit] for bit in reversed(sorted(bits)))
            result = ''.join(iterable)

        elif spec == 'ch':
            result = idaapi.xrefchar(xr)

        else:
            cls = self.__class__
            raise internal.exceptions.InvalidFormatError(u"{:s}.__format__({!r}) : An unsupported format string ({!s}) was used.".format('.'.join([cls.__name__, '__format__']), spec, spec))
        return result.decode('latin1') if isinstance(result, internal.types.bytes) else result

    def __hash__(self):
        res = self.__get_flags__()
        return hash((self.__class__, res))

    def __merge__(self, operation, other):
        cls, available = self.__class__, {character for bit, character in self.__xrflags__.items() if bit & 0xf}
        if not isinstance(other, (cls, internal.types.unordered, internal.types.string)):
            raise internal.exceptions.InvalidTypeOrValueError(u"{:s}.__merge__({!s}, {!r}) : Unable to perform {:s} operation with unsupported type `{:s}`.".format('.'.join([__name__, cls.__name__]), operation, other, operation.__name__, other.__class__.__name__))
        op1, op2 = ({item for item in op} for op in [self, other])
        flags = [flag for flag in operation(op1, op2)]
        table = {character : index for index, character in enumerate(reversed(sorted(available)))}
        bits = (table[character] for character in flags)
        res = functools.reduce(operator.or_, map(functools.partial(pow, 2), bits), 0)
        return cls(self.__xrtype, self.__xrcode).__merge_flags__(res)

    def __operator__(self, operation, other):
        cls = self.__class__
        if isinstance(other, cls):
            left, right = map(operator.methodcaller('__get_type__'), [self, other])
        elif isinstance(other, internal.types.integer):
            (left, _), right = self.__get_type__(), other
        elif isinstance(other, internal.types.tuple):
            left, right = self.__get_type__(), other
        else:
            raise internal.exceptions.InvalidTypeOrValueError(u"{:s}.__operator__({!s}, {!r}) : Unable to perform {:s} operation with unsupported type `{:s}`.".format('.'.join([__name__, cls.__name__]), operation, other, operation.__name__, other.__class__.__name__))
        return operation(left, right)

    def __and__(self, other):
        return self.__merge__(operator.and_, other)
    def __or__(self, other):
        return self.__merge__(operator.or_, other)
    def __xor__(self, other):
        return self.__merge__(operator.xor, other)
    def __sub__(self, other):
        return self.__merge__(operator.sub, other)

    # equality comparison is explicitly for checking the type of the access
    def __cmp__(self, other):
        return self.__operator__(cmp, other)
    def __eq__(self, other):
        return self.__operator__(operator.eq, other)
    def __ne__(self, other):
        return self.__operator__(operator.ne, other)
    def __lt__(self, other):
        return self.__operator__(operator.lt, other)
    def __ge__(self, other):
        return self.__operator__(operator.ge, other)
    def __gt__(self, other):
        return self.__operator__(operator.gt, other)

    def __invert__(self):
        cls, available = self.__class__, {character for bit, character in self.__xrflags__.items() if bit & 0xf}
        return self.__merge__(operator.xor, available)

    def __contains__(self, flags):
        operation = operator.contains
        if not isinstance(flags, (internal.types.unordered, internal.types.string)):
            cls = self.__class__
            raise internal.exceptions.InvalidTypeOrValueError(u"{:s}.__contains__({!s}, {!r}) : Unable to perform {:s} operation with unsupported type `{:s}`.".format('.'.join([__name__, cls.__name__]), operation, flags, operation.__name__, flags.__class__.__name__))

        # Iterate through all of our required parameters and check for their existence.
        items, required = {item for item in self}, {item for item in flags}
        return all(operation(items, item) for item in required)

    def __getitem__(self, other):
        operation = operator.contains

        # If it's an integer, then we're checking for the exact reference type.
        if isinstance(other, internal.types.integer):
            (left, _), right = self.__get_type__(), other
            return operator.eq(left, right)

        # Our parameter needs to be something we can turn into a set. Anything
        # else is not a thing since that makes it impossible to check membership.
        if not isinstance(other, (internal.types.unordered, internal.types.string)):
            raise internal.exceptions.InvalidTypeOrValueError(u"{:s}.__getitem__({!s}, {!r}) : Unable to perform {:s} operation with unsupported type `{:s}`.".format('.'.join([__name__, cls.__name__]), operation, other, operation.__name__, other.__class__.__name__))

        # Iterate through all of our required parameters and check for their existence.
        items, required = {item for item in self}, {item for item in other}
        return all(operation(items, item) for item in required)

    def __repr__(self):
        cls = self.__class__
        return "{:s}({:s})".format(cls.__name__, self)

class refbase_t(integerish):
    """
    This is a base class for dealing with references that use an `access_t`. This
    class intents to allow the user to merge references together in a couple of
    ways that can influence the `access_t` that is used by each reference.
    """

    def __get_mergable_access(self, operation, other):
        '''Return the `access_t` for the `other` parameter if the current reference can be merged with it.'''
        cls = self.__class__

        # If it's an access_t, then we're good and can just merge it.
        if isinstance(other, (access_t, internal.types.string)):
            return other

        # Otherwise we just need to verify that the addresses are the same.
        address, oaddress = map(int, [self, other])
        if address != oaddress:
            raise TypeError(u"{:s}.__{:s}__({!r}) : Unable to perform {:s} operation with type `{:s}` due to being located at a diferent address ({:#x}) from {:#x}.".format('.'.join([__name__, cls.__name__]), operation.__name__, other, operation.__name__, other.__class__.__name__, oaddress, address))

        # Now we can just blindly fetch the access_t from somewhere within.
        return next(item for item in other if isinstance(item, access_t))

    def __merge_with(self, operation, other):
        cls, state = self.__class__, [item for item in self]

        # If it's not something we can merge with the access_t, then it's another operation.
        if not isinstance(other, (refbase_t, access_t, internal.types.string)):
            return self.__operator__(operation, other)

        # Otherwise just extract the access_t merge it with ours, and reconstruct our instance.
        access = self.__get_mergable_access(operation, other)
        index = next(index for index, item in enumerate(state) if isinstance(item, access_t))
        args = state[:index] + [operation(state[index], access)] + state[1 + index:]
        return cls(*args)

    def __and__(self, other):
        return self.__merge_with(operator.and_, other)
    def __or__(self, other):
        return self.__merge_with(operator.or_, other)
    def __xor__(self, other):
        return self.__merge_with(operator.xor, other)

class ref_t(refbase_t):
    """
    This tuple is used to represent references to an address that is marked
    as data and uses the format `(address, access_t)` to describe the reference.
    """
    _fields = ('address', 'access')
    _types = (internal.types.integer, (access_t, reftype_t))
    _operands = (internal.utils.fcurry, internal.utils.fconstant)
    _formats = "{:#x}".format, "{!s}".format

    @property
    def ea(self):
        '''Return the address field that is associated with the reference.'''
        res, _ = self
        return res

    def __int__(self):
        address, _ = self
        return address

    def __same__(self, other):
        _, state = self
        _, ostate = other
        return state == ostate

    def __similar__(self, other):
        if isinstance(other, opref_t):
            _, state = self
            _, _, ostate = other
            return state & ostate
        return False

    def __repr__(self):
        cls, fields = self.__class__, {'address'}
        res = ("{!s}={:s}".format(internal.utils.string.escape(name, ''), ("{:#x}" if name in fields else "{!s}").format(value)) for name, value in zip(self._fields, self))
        return "{:s}({:s})".format(cls.__name__, ', '.join(res))

class opref_t(refbase_t):
    """
    This tuple is used to represent references that include an operand number
    and has the format `(address, opnum, access)`.
    """
    _fields = ('address', 'opnum', 'access')
    _types = (internal.types.integer, internal.types.integer, (access_t, reftype_t))
    _operands = (internal.utils.fcurry, internal.utils.fconstant, internal.utils.fconstant)
    _formats = "{:#x}".format, "{!s}".format, "{!s}".format

    @property
    def ea(self):
        '''Return the address field that is associated with the operand being referenced.'''
        res, _, _ = self
        return res

    def __int__(self):
        address, _, _ = self
        return address

    def __same__(self, other):
        _, num, state = self
        _, onum, ostate = other
        return all(this == that for this, that in [(num, onum), (state, ostate)])

    def __similar__(self, other):
        if isinstance(other, ref_t):
            _, num, state = self
            _, ostate = other
            return state & ostate
        return False

# XXX: is .startea always guaranteed to point to an instruction that modifies
#      the switch's register? if so, then we can use this to calculate the
#      .range/.cases more accurately instead of them being based on .elbase.
class switch_t(object):
    """
    This object is a wrapper around the ``idaapi.switch_info_ex_t`` class and
    allows for easily querying the semantics of the different attributes that
    are exposed by the switch_info_ex_t. A number of methods are provided
    which allow one to enumerate the valid case numbers, the handlers for them
    and any tables associated with the switch.
    """
    def __init__(self, switch_info_ex):
        self.object = switch_info_ex
    def __len__(self):
        '''Return the total number of cases (including any default) that are handled by the switch.'''
        return len(self.range)
    def has(self, ea):
        '''Return true if the switch uses the address `ea` as one of its handlers.'''
        ea, _ = ea if isinstance(ea, tuple) else (ea, None)
        handlers = {ea for ea in self.branch} | {self.object.defjump}
        return ea in handlers
    @property
    def ea(self):
        '''Return the address at the beginning of the switch.'''
        return self.object.startea
    @property
    def branch_ea(self):
        '''Return the address of the branch table containing the address of each handler.'''
        return self.object.jumps
    @property
    def indirect_ea(self):
        '''Return the address of the indirection table containing the indices for each handler.'''
        if self.object.is_indirect():
            return self.object.values
        cls = self.__class__
        clsname = "{:s}({:#x})".format(internal.utils.pycompat.fullname(cls), self.object.startea)
        raise internal.exceptions.MissingTypeOrAttribute(u"{:s}.indirect_ea() : Unable to return the indirection table for the `{:s}` at {:#x}, as it does not contain one.".format(clsname, cls.__name__, self.object.startea))
    @property
    def default(self):
        '''Return the address of the default handler for the switch.'''
        return self.object.defjump
    @property
    def branch(self):
        '''Return the contents of the branch table as a list of addresses.'''
        info, ea, count = idaapi.opinfo_t(), self.object.jumps, self.object.jcases if self.object.is_indirect() else self.object.ncases
        flags, element, ri = address.flags(ea), address.element(ea), address.refinfo(ea)
        bytes = idaapi.get_many_bytes(ea, count * element) if idaapi.__version__ < 7.0 else idaapi.get_bytes(ea, count * element)
        ok = idaapi.get_opinfo(ea, idaapi.OPND_ALL, flags, info) if idaapi.__version__ < 7.0 else idaapi.get_opinfo(info, ea, idaapi.OPND_ALL, flags)
        info = info if ok else None

        # Now we can decode the array. We mask out any reference information because
        # we're going to be translating each address we get out of it anyways.
        result = decode.array(flags & ~(idaapi.MS_0TYPE|idaapi.MS_1TYPE), info, bytes)
        if len(result) != count:
            cls = self.__class__
            clsname = "{:s}({:#x})".format(internal.utils.pycompat.fullname(cls), self.object.startea)
            logging.warning(u"{:s}.branch() : Decoding [:d} byte{:s} for the branch table at {:#x} resulted in a different number of elements ({:d}) than expected ({:d}).".format(clsname, len(bytes), '' if len(bytes) == 1 else 's', ea, len(result), count))

        # Now we can use switch_info_ex_t.elbase that we extract from our switch and use
        # it to translate the list of addresses that we decode out of our branch table.
        Ftranslate = functools.partial(operator.sub if self.object.is_subtract() else operator.add, self.object.elbase)
        return [ea for ea in map(Ftranslate, result)]
    @property
    def indirection(self):
        '''Return the contents of the indirection table as a list.'''
        info, ea, count = idaapi.opinfo_t(), self.object.lowcase if self.object.is_indirect() else self.object.jumps, self.object.ncases
        flags, element, ri = address.flags(ea), address.element(ea), address.refinfo(ea)
        ok = idaapi.get_opinfo(ea, idaapi.OPND_ALL, flags, info) if idaapi.__version__ < 7.0 else idaapi.get_opinfo(info, ea, idaapi.OPND_ALL, flags)
        info = info if ok else None

        # if we're not an indirect switch, then the index table is a list
        # of all of the available cases that the switch uses.
        if not self.object.is_indirect():
            return decode.array(flags, info, b'') or [index for index in builtins.range(count)]

        # otherwise, we can simply read the array and return it.
        bytes = idaapi.get_many_bytes(ea, count * element) if idaapi.__version__ < 7.0 else idaapi.get_bytes(ea, count * element)
        result = decode.array(flags, info, bytes)
        if len(result) != count:
            cls = self.__class__
            clsname = "{:s}({:#x})".format(internal.utils.pycompat.fullname(cls), self.object.startea)
            logging.warning(u"{:s}.indirection() : Decoding [:d} byte{:s} for the indirection table at {:#x} resulted in a different number of elements ({:d}) than expected ({:d}).".format(clsname, len(bytes), '' if len(bytes) == 1 else 's', ea, len(result), count))
        return result
    @property
    def register(self):
        '''Return the register that contains the case used by the switch.'''
        ri, rt = (self.object.regnum, self.object.regdtyp) if idaapi.__version__ < 7.0 else (self.object.regnum, self.object.regdtype)
        return architecture.by_indextype(ri, rt)
    @property
    def base(self):
        '''Return the lowest case that can be handled by the switch.'''
        res = self.object.ind_lowcase if self.object.is_indirect() else self.object.lowcase

        # assume the base case number is always signed despite ind_lowcase
        # being an sval_t and lowcase being a uval_t.
        return idaapi.as_signed(res)
    @property
    def count(self):
        '''Return the total number of cases available for the switch.'''
        return self.object.ncases
    def indirect(self):
        '''Return whether the switch references its handlers indirectly using an indirection table.'''
        return self.object.is_indirect()
    def subtract(self):
        '''Return whether the switch translates its branch table using a subtraction from the element base.'''
        return self.object.is_subtract()
    def case(self, case):
        '''Return the address for the handler belonging to the specified `case`.'''
        if not (self.base <= case < self.count + self.base):
            cls = self.__class__
            clsname = "{:s}({:#x})".format(internal.utils.pycompat.fullname(cls), self.object.startea)
            raise internal.exceptions.IndexOutOfBoundsError(u"{:s}.case({:d}) : The specified case ({:d}) was out of bounds ({:#x}..{:#x}).".format(clsname, case, case, self.base, self.base + self.count - 1))

        # Translate the case number to the index that we're supposed to use for either table.
        translated = case - self.base
        index = self.indirection[translated]
        return self.branch[index]
    def handler(self, ea):
        '''Return all of the cases that are handled by the address `ea`.'''
        ea, _ = ea if isinstance(ea, tuple) else (ea, None)
        cases = builtins.range(self.base, self.base + self.count)
        return tuple(case for case in cases if self.case(case) == ea)
    @property
    def handlers(self):
        '''Return all of the available handlers within the switch.'''
        ignored = {ea for ea in []}
        return tuple(ea for ea in self.branch if [ea not in ignored, ignored.add(ea)][0])
    @property
    def range(self):
        '''Return all of the cases that can be handled by the switch.'''
        return tuple(builtins.range(self.base, self.base + self.count))
    @property
    def cases(self):
        '''Return all of the cases in the switch that are not handled by the default handler.'''
        cases = builtins.range(self.base, self.base + self.count)

        # Define some closures that return true if an instruction branches to or references a specific address
        branches_to = lambda ea, target: instruction.is_unconditional(ea) and not instruction.is_indirect(ea) and instruction.reference(ea, 0) == target
        references_default = lambda ea, target: operator.eq(ea, target) or branches_to(ea, target)

        # And then return all cases that don't reference or immediately branch to the default case.
        return tuple(case for case in cases if not references_default(self.case(case), self.object.defjump))
    def __str__(self):
        cls = self.__class__
        if self.object.is_indirect():
            return "<class '{:s}{{{:d}}}' at {:#x}> default:{:#x} branch[{:d}]:{:#x} indirect[{:d}]:{:#x} register:{!s}".format(cls.__name__, self.count, self.object.startea, self.object.defjump, self.object.jcases, self.object.jumps, self.object.ncases, self.object.lowcase, self.register)
        return "<class '{:s}{{{:d}}}' at {:#x}> default:{:#x} branch[{:d}]:{:#x} register:{!s}".format(cls.__name__, self.count, self.object.startea, self.object.defjump, self.object.ncases, self.object.jumps, self.register)
    def __unicode__(self):
        cls = self.__class__
        if self.object.is_indirect():
            return u"<class '{:s}{{{:d}}}' at {:#x}> default:{:#x} branch[{:d}]:{:#x} indirect[{:d}]:{:#x} register:{!s}".format(cls.__name__, self.count, self.object.startea, self.object.defjump, self.object.jcases, self.object.jumps, self.object.ncases, self.object.lowcase, self.register)
        return u"<class '{:s}{{{:d}}}' at {:#x}> default:{:#x} branch[{:d}]:{:#x} register:{!s}".format(cls.__name__, self.count, self.object.startea, self.object.defjump, self.object.ncases, self.object.jumps, self.register)
    def __repr__(self):
        return u"{!s}".format(self)

class xref(object):
    """
    This namespace provides tools for interacting with the different types of
    cross-references provided by the disassembler. This includes the references
    exposed via the ``idaapi.xrefblk_t`` type and includes both "crefs" and "drefs"
    provided by the ``idaapi.get_first_cref_to`` and ``idaapi.get_first_dref_to``
    apis (respectively).
    """

    @classmethod
    def iterate(cls, ea, start, next):
        '''Iterate through the cross-references at `ea` starting with the callable `start` and continuing until the callable `next` returns false.'''
        addr = start(ea)
        while addr != idaapi.BADADDR:
            yield addr
            addr = next(ea, addr)
        return

    @internal.utils.multicase(ea=internal.types.integer, mptr=idaapi.member_t)
    @classmethod
    def frame(cls, ea, mptr):
        '''Yield each operand reference to the member `mptr` in the frame belonging to the function containing the address `ea`.'''
        fn = idaapi.get_func(ea)
        if not fn:
            return
        for opref in cls.frame(fn, mptr):
            yield opref
        return
    @internal.utils.multicase(func=idaapi.func_t, mptr=idaapi.member_t)
    @classmethod
    def frame(cls, func, mptr):
        '''Yield each operand reference to the frame member `mptr` belonging to the function `func`.'''
        xl = idaapi.xreflist_t()
        idaapi.build_stkvar_xrefs(xl, func, mptr)
        for xr in xl:
            yield xr.ea, int(xr.opnum), xr.type
        return

    @internal.utils.multicase(ea=internal.types.integer)
    @classmethod
    def to_code(cls, ea):
        '''Iterate through all the code references that reference the address `ea`.'''
        return cls.iterate(ea, idaapi.get_first_cref_to, idaapi.get_next_cref_to)
    @internal.utils.multicase(ea=internal.types.integer)
    @classmethod
    def of_code(cls, ea):
        '''Iterate through all the code references that originate from the address `ea`.'''
        return cls.iterate(ea, idaapi.get_first_cref_from, idaapi.get_next_cref_from)

    @internal.utils.multicase(ea=internal.types.integer)
    @classmethod
    def to_data(cls, ea):
        '''Iterate through all the data references that reference the address `ea`.'''
        return cls.iterate(ea, idaapi.get_first_dref_to, idaapi.get_next_dref_to)
    @internal.utils.multicase(ea=internal.types.integer)
    @classmethod
    def of_data(cls, ea):
        '''Iterate through all the data references that originate from the address `ea`.'''
        return cls.iterate(ea, idaapi.get_first_dref_from, idaapi.get_next_dref_from)

    @internal.utils.multicase(ea=internal.types.integer)
    @classmethod
    def to(cls, ea):
        '''Iterate through the cross-references that reference the identifier `ea`.'''
        return cls.to(ea, idaapi.XREF_ALL)
    @internal.utils.multicase(ea=internal.types.integer, flags=internal.types.integer)
    @classmethod
    def to(cls, ea, flags):
        '''Iterate through the cross-references of the type `flags` that reference the identifier `ea`.'''
        X = idaapi.xrefblk_t()

        # Check to see if we can find the first one and bail if we couldn't.
        if not X.first_to(ea, flags):
            return
        yield (X.frm, X.iscode, X.type)

        # Since we were able to find one, we just continue to iterate through the
        # rest of the xrefblk_t while yielding the necessary properties.
        while X.next_to():
            yield (X.frm, X.iscode, X.type)
        return

    @internal.utils.multicase(ea=internal.types.integer)
    @classmethod
    def of(cls, ea):
        '''Iterate through the cross-references that originate from the identifier `ea`.'''
        return cls.of(ea, idaapi.XREF_ALL)
    @internal.utils.multicase(ea=internal.types.integer, flags=internal.types.integer)
    @classmethod
    def of(cls, ea, flags):
        '''Iterate through the cross-references of the type `flags` that originate from the identifier `ea`.'''
        X = idaapi.xrefblk_t()

        # Check to see if we can find the first one and bail if we couldn't.
        if not X.first_from(ea, flags):
            return
        yield (X.to, X.iscode, X.type)

        # Since we were able to find one, we just continue to iterate through the
        # rest of whatever xrefblk_t returns while yielding the necessary properties.
        while X.next_from():
            yield (X.to, X.iscode, X.type)
        return

    @internal.utils.multicase(ea=internal.types.integer, target=internal.types.integer, flowtype=internal.types.integer)
    @classmethod
    def add_code(cls, ea, target, flowtype):
        '''Add a code reference originating from `ea` to `target` of the specified `flowtype`.'''
        void = idaapi.add_cref(ea, target, flowtype)
        # XXX: there's really no way to verify this was added correctly
        #      without iterating back through them.. so we have to assume.
        return True

    @internal.utils.multicase(ea=internal.types.integer, target=internal.types.integer, datatype=internal.types.integer)
    @classmethod
    def add_data(cls, ea, target, datatype):
        '''Add a data reference originating from `ea` to `target` of the specified `datatype`.'''
        void = idaapi.add_dref(ea, target, datatype)
        # XXX: there's really no way to verify this was added correctly
        #      without iterating back through them.. so we have to assume.
        return True

    @internal.utils.multicase(ea=internal.types.integer, target=internal.types.integer)
    @classmethod
    def remove_code(cls, ea, target, **expand):
        """Remove a code reference originating from `ea` to `target`.

        If the `expand` parameter is true, then also remove the instruction that is referenced by `target`.
        """
        void = idaapi.del_cref(ea, target, 1 if expand.get('expand', False) else 0)
        # XXX: there's really no way to verify this was remove correctly
        #      without iterating back through them.. so we have to assume.
        return True

    @internal.utils.multicase(ea=internal.types.integer, target=internal.types.integer)
    @classmethod
    def remove_data(cls, ea, target):
        '''Remove a data reference originating from `ea` to `target`.'''
        void = idaapi.del_dref(ea, target)
        # XXX: there's really no way to verify this was remove correctly
        #      without iterating back through them.. so we have to assume.
        return True
xiterate = internal.utils.alias(xref.iterate, 'xref')

class function(object):
    '''
    This namespace provides basic tools for locating a function and returning
    an address. It is primarily for supporting the `addressOfRuntimeOrStatic`
    function which is necessary to differentiate between actual local functions
    that that are referenced by an ``idaapi.func_t``, and external functions that
    reside in an external segment where the bytes are undefined or relocated.

    These two separate distintions are needed because the disassembler can create
    an ``idaapi.func_t`` in an external segment.. but since their contents are
    undefined there really isn't anything we can personally do with them. So, in
    order for us to handle functions consistently, we internally reference them as
    an address and convert them to a ``idaapi.func_t`` whenever needed. Despite our
    special handling, we don't do anything to prevent the user from getting an
    ``idaapi.func_t`` for these externals if they want to. Thus our distinction
    of these is really only for influencing the type of side-effect to apply.
    '''
    @classmethod
    def has(cls, ea):
        '''Return if the address `ea` is within a function and not an external.'''
        return idaapi.get_func(int(ea)) is not None and idaapi.segtype(int(ea)) != idaapi.SEG_XTRN

    @classmethod
    def by_address(cls, ea):
        '''Return the ``idaapi.func_t`` that contains the address `ea`.'''
        return idaapi.get_func(int(ea))

    @classmethod
    @internal.utils.string.decorate_arguments('name')
    def by_name(cls, name):
        '''Return the ``idaapi.func_t`` for the function using the specified `name`.'''
        ea = idaapi.get_name_ea(idaapi.BADADDR, internal.utils.string.to(name))
        return None if ea == idaapi.BADADDR else idaapi.get_func(ea)

    @classmethod
    def by_frame(cls, sptr):
        '''Return the ``idaapi.func_t`` for the function that owns the frame specified in `sptr`.'''
        if sptr.props & idaapi.SF_FRAME:
            ea = idaapi.get_func_by_frame(sptr.id)
            return None if ea == idaapi.BADADDR else idaapi.get_func(ea)
        return None

    @internal.utils.multicase(func=idaapi.func_t)
    @classmethod
    def by(cls, func):
        '''Return the function identified by `func`.'''
        return func
    @internal.utils.multicase(ea=internal.types.integer)
    @classmethod
    def by(cls, ea):
        '''Return the function at the address `ea`.'''
        return cls.by_address(ea)
    @internal.utils.multicase(name=internal.types.string)
    @classmethod
    def by(cls, name):
        '''Return the function with the specified `name`.'''
        return cls.by_name(name)
    @internal.utils.multicase(frame=idaapi.struc_t)
    @classmethod
    def by(cls, frame):
        '''Return the function that owns the specified `frame`.'''
        return cls.by_frame(frame)
    @internal.utils.multicase()
    @classmethod
    def by(cls, unsupported):
        '''Raise an exception due to receiving an `unsupported` type.'''
        raise internal.exceptions.FunctionNotFoundError(u"{:s}.by({!r}) : Unable to locate a function using an unsupported type ({!s}).".format('.'.join([cls.__name__]), unsupported, internal.utils.pycompat.fullname(unsupported.__class__)))

    @internal.utils.multicase(name=internal.types.string)
    @classmethod
    def missing(cls, name):
        '''Raise an exception related to the `name` not being found.'''
        raise internal.exceptions.FunctionNotFoundError(u"{:s}.by({!r}) : Unable to locate a function with the specified name ({!s}).".format('.'.join([cls.__name__]), name, internal.utils.string.repr(name)))
    @internal.utils.multicase(ea=internal.types.integer)
    @classmethod
    def missing(cls, ea):
        '''Raise an exception related to the address in `ea` not pointing to a function.'''
        raise internal.exceptions.FunctionNotFoundError(u"{:s}.by({:#x}) : Unable to locate a function at the specified address ({:#x}).".format('.'.join([cls.__name__]), ea, ea))
    @internal.utils.multicase(frame=idaapi.struc_t)
    @classmethod
    def missing(cls, frame):
        '''Raise an exception related to the structure in `frame` not being part of a function.'''
        name = utils.string.of(idaapi.get_struc_name(frame.id))
        raise internal.exceptions.FunctionNotFoundError(u"{:s}.by({:#x}) : Unable to locate a function using a structure ({!s}) that is not a frame.".format('.'.join([cls.__name__]), frame.id, internal.utils.string.repr(name)))
    @internal.utils.multicase()
    @classmethod
    def missing(cls, unsupported):
        '''Raise an exception due to receiving an `unsupported` type.'''
        raise internal.exceptions.FunctionNotFoundError(u"{:s}.by({!r}) : Unable to locate a function using an unsupported type ({!s}).".format('.'.join([cls.__name__]), unsupported, internal.utils.pycompat.fullname(unsupported.__class__)))

def addressOfRuntimeOrStatic(func):
    """Used to determine if `func` is a statically linked address or a runtime-linked address.

    This returns a tuple of the format `(runtime, address)` where
    `runtime` is a boolean returning true if the symbol is linked
    during runtime and `address` is the address of the entrypoint.
    """
    fn = function.by_address(int(func)) if isinstance(func, internal.types.integer) or hasattr(func, '__int__') else function.by_name(func) if isinstance(func, internal.types.string) else function.by_frame(func) if isinstance(func, idaapi.struc_t) else func if isinstance(func, idaapi.func_t) else function.by(func)

    # If we were able to get the function, then we need to check if it was because
    # the function is external. We extract its address and make sure it exists.
    if fn:
        ea = range.start(fn)

        # If the function address is an external, then we found a mis-defined
        # import (thx ida). Otherwise, this is a regular function and we're good.
        return (True, ea) if idaapi.segtype(ea) == idaapi.SEG_XTRN else (False, ea)

    # If we couldn't find a function, then we need to do some checks before we
    # confirm that this is a runtime-linked function. We first check that we
    # were given an integer. Although the disassembler can reference imports by
    # name, we choose not to in order to distinguish actual functions from them.
    if not isinstance(func, internal.types.integer):
        raise function.missing(func)

    # Next we check the flags to ensure that we're only referencing data or code.
    # This is because on ELF, it's registered as code and PECOFF as data.
    if address.flags(func, idaapi.MS_CLS) not in {idaapi.FF_DATA, idaapi.FF_CODE}:
        raise function.missing(func)

    # Now our final check is to verify this is defined in an external segment.
    if idaapi.segtype(func) != idaapi.SEG_XTRN:
        raise function.missing(func)

    # Yep, now we should be pretty sure that this references an external function.
    return True, func

## internal enumerations that idapython missed
class fc_block_type_t(object):
    """
    This namespace contains a number of internal enumerations for
    ``idaapi.FlowChart`` that were missed by IDAPython. This can
    be used for checking the type of the various elements within
    an ``idaapi.FlowChart``.
    """
    fcb_normal = 0  # normal block
    fcb_indjump = 1 # block ends with indirect jump
    fcb_ret = 2     # return block
    fcb_cndret = 3  # conditional return block
    fcb_noret = 4   # noreturn block
    fcb_enoret = 5  # external noreturn block (does not belong to the function)
    fcb_extern = 6  # external normal block
    fcb_error = 7   # block passes execution past the function end

class collect_t(object):
    """
    This type is used by coroutines in order to aggregate values
    that are yielded by coroutines. It implements the receiver
    part of a coroutine.
    """
    def __init__(self, cons, f):
        '''Constructs a type using `cons` as the constructor and a callable `f` used to coerce a value into the constructed type.'''
        self.__cons__, self.__agg__ = cons, f
        self.reset()

    def type(self):
        '''Return the constructor that is used for the state.'''
        return self.__cons__

    def reset(self):
        '''Reset the current state.'''
        self.__state__ = self.__cons__()
        return self

    def send(self, value):
        '''Given a `value`, aggregate it into the current state.'''
        f, state = self.__agg__, self.__state__
        self.__state__ = res = f(state, value)
        return res

    def get(self):
        '''Return the current state of the constructed type.'''
        return self.__state__

    def __repr__(self):
        t = self.__cons__
        return "{!s} {!s} -> {!r}".format(self.__class__, getattr(t, '__name__', t), self.__state__)

class bounds_t(integerish):
    """
    This tuple is used to represent references that describe a bounds
    and has the format `(left, right)` where `right` is exclusive.
    """
    _fields = ('left', 'right')
    _types = (internal.types.integer, internal.types.integer)
    _operands = (internal.utils.fcurry, internal.utils.fcurry)
    _formats = "{:#x}".format, "{:#x}".format

    def __new__(cls, *args, **kwargs):
        if len(args) == 2 and not kwargs:
            return super(bounds_t, cls).__new__(cls, *sorted(args))

        # create a mapping containing our individual fields given with our
        # arguments. the keyword parameters are given secondary priority to
        # any argument parameters.
        fields = {fld : item for fld, item in zip(cls._fields, args)}
        [ fields.setdefault(fld, kwargs.pop(fld)) for fld in cls._fields if fld in kwargs ]

        # if the size was provided, then we can use it to calculate the
        # right size of our boundaries.
        if all(item in fields for item in cls._fields) and 'size' in kwargs:
            raise TypeError("{!s}() got unexpected keyword argument{:s} {:s}".format(cls.__name__, '' if len(kwargs) == 1 else 's', ', '.join(map("'{!s}'".format, kwargs))))

        elif 'left' in fields and 'size' in kwargs:
            fields.setdefault('right', fields['left'] + kwargs.pop('size'))

        # at this point, we should have all our boundaries. it kwargs has
        # anything left in it or any required fields are not defined, then
        # raise an exception because invalid parameters were passed to us.
        if len(kwargs):
            raise TypeError("{!s}() got unexpected keyword argument{:s} {:s}".format(cls.__name__, '' if len(kwargs) == 1 else 's', ', '.join(map("'{!s}'".format, kwargs))))
        if any(item not in fields for item in cls._fields):
            available, required = ({item for item in items} for items in [fields, cls._fields])
            missing = required - available
            raise TypeError("{!s}() is missing required field{:s} {:s}".format(cls.__name__, '' if len(missing) == 1 else 's', ', '.join(map("'{!s}'".format, (item for item in cls._fields if item in missing)))))

        # now we can use our fields to construct our type properly.
        args = (fields[item] for item in cls._fields)
        return super(bounds_t, cls).__new__(cls, *sorted(args))

    @property
    def size(self):
        '''Return the size of the area described by this boundary.'''
        left, right = self
        return right - left if left < right else left - right

    @property
    def bits(self):
        '''Return the size of the area described by this boundary in bits.'''
        return 8 * self.size

    @property
    def type(self):
        '''Return the pythonic type that may contain this boundary.'''
        return [(int, 1), self.size]

    @property
    def top(self):
        '''Return the minimum address for the current boundary.'''
        left, right = self
        return min(left, right)

    @property
    def bottom(self):
        '''Return the maximum address for the current boundary.'''
        left, right = self
        return max(left, right)

    def range(self):
        '''Return the current boundary casted to a native ``idaapi.range_t`` type.'''
        left, right = sorted(self)
        return idaapi.area_t(left, right) if idaapi.__version__ < 7.0 else idaapi.range_t(left, right)

    def contains(self, ea):
        '''Return if the address `ea` is contained by the current boundary.'''
        left, right = sorted(self)
        if isinstance(ea, internal.types.integer):
            return left <= ea < right

        # compare against another boundary
        elif isinstance(ea, internal.types.tuple):
            other_left, other_right = ea
            return self.contains(other_left) if other_left == other_right else all([left <= other_left, right >= other_right])

        # anything else is an invalid type
        raise internal.exceptions.InvalidTypeOrValueError(u"{!s}.contains({!s}) : Unable to check containment with the provided type ({!s}).".format(self, ea, ea.__class__))
    __contains__ = contains

    def overlaps(self, bounds):
        '''Return if the boundary `bounds` overlaps with the current boundary.'''
        left, right = sorted(self)
        if isinstance(bounds, internal.types.integer):
            return left <= bounds < right

        other_left, other_right = sorted(bounds)
        return self.overlaps(other_left) if other_left == other_right else all([left < other_right, right > other_left])

    def union(self, other):
        '''Return a union of the current boundary with `other`.'''
        if isinstance(other, internal.types.integer):
            other = self.__class__(other, other)

        # if it's not a tuple, then fall-back to whatever our parent decides.
        elif not isinstance(other, internal.types.tuple):
            return super(bounds_t, self).__or__(other)

        (left, right), (other_left, other_right) = map(sorted, [self, other])
        return self.__class__(min(left, other_left), max(right, other_right))

    def __or__(self, other):
        '''Return a union of the current boundary with `other` unless it is an integer which will result in a binary-or with its values.'''
        return super(bounds_t, self).__or__(other) if isinstance(other, internal.types.integer) else self.union(other)

    def intersection(self, other):
        '''Return an intersection of the current boundary with `other`.'''
        if isinstance(other, internal.types.integer):
            other = self.__class__(other, other)

        # if it's not a tuple, then fall-back to whatever our parent decides.
        elif not isinstance(other, internal.types.tuple):
            return super(bounds_t, self).__and__(other)

        # if they don't overlap, then we can't intersect and so we bail.
        if not self.overlaps(other):
            raise internal.exceptions.InvalidTypeOrValueError(u"{!s}.intersection({!s}) : Unable to intersect with a non-overlapping boundary ({!s}).".format(self, other, other))

        (left, right), (other_left, other_right) = map(sorted, [self, other])
        return self.__class__(max(left, other_left), min(right, other_right))

    def __and__(self, other):
        '''Return an intersection of the current boundary with `other` unless it is an integer which will result in a binary-and with its values.'''
        return super(bounds_t, self).__and__(other) if isinstance(other, internal.types.integer) else self.intersection(other)

    def __format__(self, spec):
        '''Return the current boundary as a string containing only the components that are inclusive to the range.'''
        if spec != 's':
            cls = self.__class__
            raise TypeError("unsupported format string ({!s}) passed to {:s}".format(spec, '.'.join([cls.__name__, '__format__'])))
        left, right = sorted(self)
        if left < right - 1:
            return "{:#x}..{:#x}".format(left, right - 1)
        return "{:#x}".format(left)

    def __mul__(self, count):
        '''Grow the boundary `count` times in the specified direction.'''
        left, right = self
        sign, size = -1 if count < 0 else +1, right - left if left < right else left - right
        translate = (size * count, size * sign) if count < 0 else (0, -size + size * count)
        return self.__class__(*itertools.starmap(operator.add, zip(self, translate)))
    __rmul__ = __mul__

    def __pow__(self, index):
        '''Return the boundary translated to the specified `index` of an array.'''
        left, right = self
        size = right - left if left < right else left - right
        translate = functools.partial(operator.add, self.size * index)
        return self.__class__(*sorted(map(translate, self)))

    def __invert__(self):
        return operator.neg(self)

# FIXME: should probably be a register_t, but with the different attributes
class partialregister_t(namedtypedtuple, symbol_t):
    _fields = 'register', 'position', 'bits'
    _types = register_t, internal.types.integer, internal.types.integer
    _operands = internal.utils.fconstant, internal.utils.fcurry, internal.utils.fcurry

    def __hash__(self):
        cls = self.__class__
        register, position, bits = self
        return hash((cls, register, position, bits))

    @property
    def symbols(self):
        '''Yield the symbolic components that compose the register part.'''
        register, _, _ = self
        yield register

    @property
    def size(self):
        '''Return the size of the register part in bytes.'''
        _, _, bits = self
        return bits // 8

    @property
    def type(self):
        '''Return the pythonic type of the current register part.'''
        _, _, bits = self
        return builtins.int, bits // 8

    @property
    def bytes(self):
        '''Return the bytes that make up the value of the current register part.'''
        register, position, bits = self
        index, size = position // 8, bits // 8
        return register.bytes[index : index + size]

    def __int__(self):
        '''Return the integer value of the current register part.'''
        bytes = bytearray(self.bytes)
        return functools.reduce(lambda agg, item: agg * 0x100 + item, bytes, 0)

    def __float__(self):
        '''Return the floating-point value of the current register part.'''
        raise internal.exceptions.InvalidTypeOrValueError(u"{!s} : Unable to resolve as a floating-point number.".format(self, rv.rvtype))

class location_t(integerish):
    """
    This tuple is used to represent the size at a given location and has the format `(offset, size)`.
    """
    _fields = ('offset', 'size')
    _types = ((internal.types.integer, register_t), internal.types.integer)
    _operands = (internal.utils.fcurry, internal.utils.fconstant)
    _formats = lambda offset: "{:#x}".format(offset) if isinstance(offset, internal.types.integer) else "{!s}".format(offset), "{:d}".format

    def __new__(cls, offset, size):
        return super(location_t, cls).__new__(cls, offset, max(0, size))

    def __int__(self):
        offset, size = self
        if isinstance(offset, internal.types.integer):
            return offset

        elif isinstance(offset, symbol_t):
            symbol, = offset.symbols
            return int(offset)

        cls = self.__class__
        raise internal.exceptions.InvalidTypeOrValueError(u"{!s} : Unable to convert the location offset ({!s}) to an integer.".format(self, offset))

    def __same__(self, other):
        thisoffset, thissize = self
        thatoffset, thatsize = other
        return all([thisoffset == thatoffset, thissize == thatsize])

    @property
    def bits(self):
        '''Return the size of the location in bits.'''
        offset, size = self
        return 8 * size

    @property
    def symbols(self):
        '''Yield the symbolic components of this location.'''
        offset, size = self
        if not isinstance(offset, internal.types.integer):
            yield offset
        return

    @property
    def type(self):
        '''Return the pythonic type describing this location.'''
        offset, size = self

        # if our size is in the typemap's integermap, then we can simply use it.
        if size in typemap.integermap:
            return int, size

        # otherwise, we need to form ourselves into an array of bytes.
        return [(int, 1), size]

    @property
    def bounds(self):
        '''Return the boundaries of the current location as a ``bounds_t``.'''
        offset, size = self
        if isinstance(offset, internal.types.integer):
            return bounds_t(offset, offset + size)

        # If the offset is a symbol, then we can try for an integer if possible.
        elif isinstance(offset, symbol_t):
            symbol, = offset.symbols
            offset = int(offset)
            return bounds_t(offset, offset + size)

        raise internal.exceptions.InvalidTypeOrValueError(u"{!s} : Unable to convert the location offset ({!s}) to an integer.".format(self, offset))

    def range(self):
        '''Return the current location casted to a native ``idaapi.range_t`` type.'''
        return self.bounds.range()

    def contains(self, offset):
        '''Return if the given `offset` is contained by the current location.'''
        return self.bounds.contains(offset)
    __contains__ = contains

    def __neg__(self):
        offset, size = self
        res = int(offset)
        bounds = map(functools.partial(operator.mul, -1), [res, res + size])
        left, right = sorted(bounds)
        return self.__class__(left, right - left)

    def __invert__(self):
        offset, size = self
        return self.__class__(int(offset) * -1, size)

    def __mul__(self, count):
        '''Grow the location `count` times in the specified direction.'''
        offset, size = self
        translate = size * count
        if count < 0:
            offset, res = int(offset), size * count
            return self.__class__(offset + res, abs(res))
        res = size * count
        return self.__class__(offset, res)

    def __pow__(self, index):
        '''Return the boundary translated to the specified `index` of an array.'''
        offset, size = self
        return self.__class__(int(offset) + size * index, size)

class phrase_t(integerish, symbol_t):
    """
    This tuple is used to represent a phrase relative to a register and has the format `(register, offset)`.
    """
    _fields = 'register', 'offset'
    _types = (register_t, partialregister_t), internal.types.integer
    _operands = internal.utils.fconstant, internal.utils.fcurry
    _formats = "{!s}".format, "{:#x}".format

    def __hash__(self):
        cls = self.__class__
        register, offset = self
        return hash((cls, register, offset))

    @property
    def symbols(self):
        '''Yield the register part of the tuple.'''
        register, _ = self
        yield register

    def __int__(self):
        '''Return the offset part of the tuple.'''
        _, offset = self
        return offset

    def __same__(self, other):
        register, _ = self
        oregister, _ = other
        return any([register is None, oregister is None, register == oregister])

class decode(object):
    """
    This namespace is directly responsible for mapping the disassembler's
    types directly to lengths, Python typecodes, or Python's ctypes so
    that the database contents can be decoded and acted upon.
    """

    # This numerics table is responsible for mapping an idaapi.DT_TYPE
    # type to a typecode that is used by Python's array module. We can
    # dual-use this since we only need to change the case for signedness.
    integer_typecode = {
        idaapi.FF_BYTE : internal.utils.get_array_typecode(1), idaapi.FF_ALIGN : internal.utils.get_array_typecode(1),
        idaapi.FF_WORD : internal.utils.get_array_typecode(2),
        idaapi.FF_DWORD if hasattr(idaapi, 'FF_DWORD') else idaapi.FF_DWRD : internal.utils.get_array_typecode(4),
        idaapi.FF_FLOAT : 'f',
        idaapi.FF_DOUBLE : 'd',
    }

    # Some 32-bit versions of python might not have array.array('Q')
    # and some versions of IDA also might not have FF_QWORD..
    try:
        _array.array(internal.utils.get_array_typecode(8))
        integer_typecode[idaapi.FF_QWORD if hasattr(idaapi, 'FF_QWORD') else idaapi.FF_QWRD] = internal.utils.get_array_typecode(8)
    except (AttributeError, ValueError):
        pass

    # This table is a mapping-type for converting an idaapi.DT_TYPE to
    # a length. This way we can manually read the elements of the array
    # into a list that we can return to the user.
    length_table = {
        idaapi.FF_BYTE : 1, idaapi.FF_ALIGN : 1,
        idaapi.FF_WORD : 2,
        idaapi.FF_DWORD if hasattr(idaapi, 'FF_DWORD') else idaapi.FF_DWRD : 4,
        idaapi.FF_FLOAT : 4,
        idaapi.FF_DOUBLE : 8,
    }

    # Define a temporary closure that will be used to update the length table
    # with the correct size for FF_QWORD if it's available in the disassembler.
    def update_length_table(table):
        '''This function will try to update the given `table` with the correct size for an ``idaapi.FF_QWORD``.'''
        attribute = builtins.next(attribute for attribute in {'FF_QWRD', 'FF_QWORD'} if hasattr(idaapi, attribute))
        value = getattr(idaapi, attribute)
        if value not in table:
            table[value] = 8
        return

    # If we have FF_QWORD defined but it cannot be represented by the
    # _array class, then we'll need to add its size to our length-table
    # so that we can still read its elements manually.
    if hasattr(idaapi, 'FF_QWRD') or hasattr(idaapi, 'FF_QWORD'):
        update_length_table(length_table)
    del(update_length_table)

    # FF_OWORD, FF_YWORD and FF_ZWORD might not exist in older versions
    # of IDA, so try to add them softly to our length-table and bail if
    # we received an exception due to any of them not being available.
    try:
        length_table[idaapi.FF_QWORD if hasattr(idaapi, 'FF_QWORD') else idaapi.FF_QWRD] = 8
        length_table[idaapi.FF_OWORD if hasattr(idaapi, 'FF_OWORD') else idaapi.FF_OWRD] = 16
        length_table[idaapi.FF_YWORD if hasattr(idaapi, 'FF_YWORD') else idaapi.FF_YWRD] = 32
        length_table[idaapi.FF_ZWORD if hasattr(idaapi, 'FF_ZWORD') else idaapi.FF_ZWRD] = 64
    except AttributeError:
        pass

    # Depending on the version of IDAPython, some of IDA's flags (FF_*) can
    # be signed or unsigned. Since we're explicitly testing for them by using
    # container membership, we'll need to ensure that they're unsigned when
    # storing them into their lookup tables. This way our membership tests
    # will actually work when determining the types to use.
    integer_typecode = { idaapi.as_uint32(ff) : typecode for ff, typecode in integer_typecode.items() }
    length_table = { idaapi.as_uint32(ff) : length for ff, length in length_table.items() }

    # Py's "u" typecode for their _array can actually change size depending
    # on the platform. So we need to figure it out ourselves and then just
    # fall back to the integer typecode if the character ones don't exist.
    string_typecode = {
        1: 'c' if sys.version_info.major < 3 else internal.utils.get_array_typecode(1),
        2: 'u' if _array.array('u').itemsize == 2 else internal.utils.get_array_typecode(2),
        4: 'u' if _array.array('u').itemsize == 4 else internal.utils.get_array_typecode(4),
    }

    @classmethod
    def byteorder(cls, **byteorder):
        '''Process the keyword arguments in `byteorder` and return either "big" or "little" representing the byte order to use.'''
        args = ['order', 'byteorder']

        # If we weren't given a byteorder, then we just take the default order from the database.
        if not any(arg in byteorder for arg in args):
            information = idaapi.get_inf_structure()
            mf = idaapi.cvar.inf.mf if idaapi.__version__ < 7.0 else information.lflags & idaapi.LFLG_MSF
            return 'big' if mf else 'little'

        # Otherwise, we were given a byteorder as a keyword and we can use it.
        iterable = (byteorder[arg] for arg in args if arg in byteorder and byteorder[arg] in {'big', 'little'})
        order = next(iterable, None)

        # Verify the order before we return it back to the caller.
        if not isinstance(order, internal.types.string) or order.lower() not in {'big', 'little'}:
            raise internal.exceptions.InvalidParameterError(u"{:s}.byteorder({:s}) : An invalid byteorder ({:s}) that is not \"{:s}\" or \"{:s}\" was specified.".format('.'.join([__name__, cls.__name__]), internal.utils.string.kwargs(byteorder), "\"{:s}\"".format(order) if isinstance(order, internal.types.string) else "{!s}".format(order), 'big', 'little'))
        return order

    @classmethod
    def unsigned(cls, bytes):
        '''Decode the provided `bytes` into an unsigned integer.'''
        data = bytearray(bytes)
        return functools.reduce(lambda agg, byte: agg << 8 | byte, data, 0)

    @classmethod
    def signed(cls, bytes):
        '''Decode the provided `bytes` into a signed integer.'''
        bits = 8 * len(bytes)
        result, signflag = cls.unsigned(bytes), pow(2, bits) // 2
        return (result - pow(2, bits)) if result & signflag else result

    binary_float_table = {
        16 : (11, 5),
        32 : (24, 8),
        64 : (53, 11),
        128 : (113, 15),
        256 : (237, 19),
        # FIXME: we could probably add the base-10 formats too.
    }

    @classmethod
    def float(cls, bytes):
        '''Decode the provided `bytes` into an IEEE754 half, single, or double depending on its size.'''
        integer, bits = cls.unsigned(bytes), 8 * len(bytes)
        mantissa, exponent = cls.binary_float_table[bits if bits in cls.binary_float_table else next(item for item in sorted(cls.binary_float_table) if bits <= item)]
        return internal.utils.float_of_integer(integer, mantissa - 1, exponent, 1)

    @classmethod
    def element(cls, dtype):
        '''Return the element size for the given `dtype` if it is supported and can be decoded into an array.'''
        return cls.length_table.get(dtype & idaapi.DT_TYPE, 0)

    @classmethod
    def integers(cls, dtype, bytes):
        '''Decode `bytes` into an array of integers that are of the specified `dtype`.'''
        typecode = cls.integer_typecode[dtype & idaapi.DT_TYPE]

        # Create an _array using the typecode that we determined so that it can
        # be decoded and then returned to the caller.
        Ftranslate = operator.methodcaller('lower' if dtype & idaapi.FF_SIGN else 'upper')
        result = _array.array(typecode if typecode in 'fd' else Ftranslate(typecode))

        # If our _array's itemsize doesn't match the element size that we expected,
        # then we need to warn the user that something fucked up and that we're
        # hijacking the array decoding with our own hardcoded unsigned length.
        cb = cls.length_table[dtype & idaapi.DT_TYPE]
        if result.itemsize != cb:
            element = result.itemsize

            # Reconstruct the array but with the expected element size.
            try:
                result = _array.array(internal.utils.get_array_typecode(cb, 1))

            # If we can't use the typecode determined by the element size, then
            # just assume that the elements are just individual bytes.
            except ValueError:
                result = _array.array(internal.utils.get_array_typecode(1))
            logging.warning(u"{:s}.integers({:#x}, {!s}) : Using a different element size ({:+d}) due to the size ({:+d}) detected for the given flags ({:#x}) not matching the array item size ({:+d}).".format('.'.join([__name__, cls.__name__]), dtype, '...', result.itemsize, cb, dtype, element))

        # Check to see that the number of bytes we're decoding from corresponds
        # to the length of each individual array element.
        mask = result.itemsize - 1
        if result.itemsize and len(bytes) % result.itemsize:
            extra = len(bytes) & mask
            logging.info(u"{:s}.integers({:#x}, {!s}) : The amount of data available ({:#x}) for decoding is not a multiple of the element size ({:d}) and will result in discarding {:+d} byte{:s} when decoding.".format('.'.join([__name__, cls.__name__]), dtype, '...', len(bytes), result.itemsize, extra, '' if extra == 1 else 's'))
            bytes = bytes[:-extra] if extra else bytes

        # Now we can use the bytes we were given to initialize the _array
        # that we're going to return to the user.
        result.fromstring(builtins.bytes(bytes)) if sys.version_info.major < 3 else result.frombytes(bytes)
        return result

    @classmethod
    def string(cls, width, bytes):
        '''Decode the provided `bytes` as an array containing characters of the specified `width`.'''
        typecode = cls.string_typecode[width]
        result = _array.array(typecode)
        mask = result.itemsize - 1
        if result.itemsize and len(bytes) % result.itemsize:
            extra = len(bytes) & mask
            logging.warning(u"{:s}.string({:d}, ...) : The amount of data available ({:#x}) for decoding is not a multiple of the requested character width ({:d}) and will result in discarding {:+d} byte{:s} when decoding the string.".format('.'.join([__name__, cls.__name__]), width, len(bytes), result.itemsize, extra, '' if extra == 1 else 's'))
            bytes = bytes[:-extra] if extra else bytes
        result.fromstring(builtins.bytes(bytes)) if sys.version_info.major < 3 else result.frombytes(bytes)
        return result

    @classmethod
    def list(cls, width, bytes):
        '''Decode the provided `bytes` as a list where each element is the specified `width`.'''
        iterable = iter(bytearray(bytes))
        items = zip(*[iterable] * width)
        return [bytearray(item) for item in items]

    @classmethod
    def partial(cls, width, bytes):
        '''Decode the provided `bytes` into a list where each element is the specified `width` leaving any extra bytes that did not fit as the last element.'''
        size, padding, extra = max(0, width), width - 1, len(bytes) % width if width > 0 else 0
        iterable = itertools.chain(bytes, b'\0' * padding)
        items = zip(*[iter(bytearray(iterable))] * size)
        result = [bytearray(item) for item in items]
        return [item for item in itertools.chain(result[:-1], [result[-1][:extra]])] if extra else result

    # This table is just used for converting a pythonic-type into
    # a ctype. We use ctypes because an instance of a ctype has the
    # added effect of giving us a size and a few other features which
    # allows us to avoid implementing a complete and proper typesystem.
    ctype_table = {
        (int, -1) : ctypes.c_int8,   (int, 1) : ctypes.c_uint8,
        (int, -2) : ctypes.c_int16,  (int, 2) : ctypes.c_uint16,
        (int, -4) : ctypes.c_int32,  (int, 4) : ctypes.c_uint32,
        (int, -8) : ctypes.c_int64,  (int, 8) : ctypes.c_uint64,
        (float, 4) : ctypes.c_float, (float, 8) : ctypes.c_double,

        # pointer types, would be cool if we could have variable-sized pointers..but we don't.
        (builtins.type, -1) : ctypes.c_int8,    (builtins.type, 1) : ctypes.c_uint8,
        (builtins.type, -2) : ctypes.c_int16,   (builtins.type, 2) : ctypes.c_uint16,
        (builtins.type, -4) : ctypes.c_int32,   (builtins.type, 4) : ctypes.c_uint32,
        (builtins.type, -8) : ctypes.c_int64,   (builtins.type, 8) : ctypes.c_uint64,
    }

    @classmethod
    def union_bytes(cls, sptr, bytes):
        '''Use the union specified by `sptr` with the specified `bytes` to return a dictionary of the individual fields and the bytes that compose them.'''
        SF_VAR, SF_UNION = getattr(idaapi, 'SF_VAR', 0x1), getattr(idaapi, 'SF_UNION', 0x2)
        if not (sptr.props & SF_UNION):
            raise internal.exceptions.InvalidTypeOrValueError(u"{:s}.union_bytes({:#x}, ...) : The `{:s}` for the requested identifier ({:#x}) is not a `{:s}`.".format('.'.join([__name__, cls.__name__]), sptr.id, internal.utils.pycompat.fullname(sptr.__class__), sptr.id, 'SF_UNION'))

        # Iterate through each union member and use their size to stash the
        # bytes that are neccessary for decoding each member. We assign the
        # entire bytes used for decoding to an empty member in case the user
        # has some need to want to access the decoded data themselves.
        result, data = {'': bytearray(bytes)}, bytearray(bytes)
        for m in internal.structure.new(sptr.id, 0).members:
            name, mptr, size = m.name, m.ptr, m.size
            if len(data) < size:
                logging.warning(u"{:s}.union_bytes({:#x}, ...) : Unable to read member ({:#x}) with the name \"{:s}\" at index {:d} of the union due to there being only {:+#x} byte{:s} worth of data available.".format('.'.join([__name__, cls.__name__]), sptr.id, mptr.id, name, mptr.soff, len(bytes), '' if len(bytes) == 1 else 's'))
            result[name] = data[:size]

        # Figure out if there was anything that we didn't decode and assign them
        # with the maximum offset in case the user wants to see what was missed.
        maximum = max(len(item) for name, item in result.items() if name) if result else 0
        result.setdefault(maximum, data[maximum:]) if maximum <= len(data) else None
        return result

    @classmethod
    def fragment_bytes(cls, sptr, bytes):
        '''Use the structure specified by `sptr` with the specified `bytes` to return a dictionary of the individual fields and the bytes that compose them.'''
        SF_VAR, SF_UNION = getattr(idaapi, 'SF_VAR', 0x1), getattr(idaapi, 'SF_UNION', 0x2)
        if sptr.props & SF_UNION:
            raise internal.exceptions.InvalidTypeOrValueError(u"{:s}.fragment_bytes({:#x}, ...) : The `{:s}` for the requested identifier ({:#x}) is a `{:s}`.".format('.'.join([__name__, cls.__name__]), sptr.id, internal.utils.pycompat.fullname(sptr.__class__), sptr.id, 'SF_UNION'))

        offset, result, data = 0, {}, bytearray(bytes)
        for m in internal.structure.new(sptr.id, 0).members:
            name, mptr = m.name, m.ptr
            left, right = 0 if sptr.props & SF_UNION else mptr.soff, mptr.eoff

            # First check our offset against the member boundaries in case there's an undefined
            # field that contains unused data. If so, use the current offset as its key.
            if offset < left:
                result[offset], offset = data[offset : left], left

            # If this is a variable-length structure and the size is 0, then we just stash everything.
            if sptr.props & SF_VAR and left == right:
                result[name] = data[left:]

            # Otherwise, we just grab the bounds that we know of and we can use it later.
            else:
                result[name] = data[left : right]

            if len(result[name]) < right - left:
                logging.warning(u"{:s}.fragment_bytes({:#x}, ...) : Unable to read member ({:#x}) with the name \"{:s}\" at offset {:#x}..{:#x} of structure due to there being only {:+#x} byte{:s} worth of data available (expected {:+d} byte{:s} more).".format('.'.join([__name__, cls.__name__]), sptr.id, mptr.id, name, left, right, len(bytes), '' if len(bytes) == 1 else 's', right - len(bytes), '' if right - len(bytes) == 1 else 's'))
            offset = right

        # If there's any data that was left unused, then we end of the last member as the
        # key and store the rest of the data inside of it so that it's still usable.
        if data[offset:]:
            result.setdefault(offset, data[offset:])
        return result

    @classmethod
    def structure_bytes(cls, identifier, bytes):
        '''Use the structure specified by `identifier` with the specified `bytes` to return a dictionary of the individual fields and the bytes that compose them.'''
        SF_VAR, SF_UNION = getattr(idaapi, 'SF_VAR', 0x1), getattr(idaapi, 'SF_UNION', 0x2)

        sptr = idaapi.get_struc(identifier)
        if not sptr:
            raise internal.exceptions.StructureNotFoundError(u"{:s}.structure_bytes({:#x}, ...) : The `{:s}` for the requested identifier ({:#x}) was not found.".format('.'.join([__name__, cls.__name__]), sptr.id, internal.utils.pycompat.fullname(sptr.__class__), sptr.id))
        return cls.union_bytes(sptr, bytes) if sptr.props & SF_UNION else cls.fragment_bytes(sptr, bytes)

    @classmethod
    def structure(cls, identifier, fields, **byteorder):
        '''Use the structure specified by `identifier` with the bytes in `fields` to return a dictionary of the decoded fields.'''
        FF_STRUCT = idaapi.FF_STRUCT if hasattr(idaapi, 'FF_STRUCT') else idaapi.FF_STRU
        FF_STRLIT = idaapi.FF_STRLIT if hasattr(idaapi, 'FF_STRLIT') else idaapi.FF_ASCI
        FF_FLOAT, FF_DOUBLE = (idaapi.as_uint32(ff) for ff in [idaapi.FF_FLOAT, idaapi.FF_DOUBLE])
        SF_VAR, SF_UNION = getattr(idaapi, 'SF_VAR', 0x1), getattr(idaapi, 'SF_UNION', 0x2)

        # Extract the byteorder from the keywords and use it to generate two callables for flipping the order.
        order = cls.byteorder(**byteorder))
        Fordered = (lambda length, data: data) if order.lower() == 'big' else (lambda length, data: functools.reduce(operator.add, (item[::-1] for item in cls.list(length, data))) if data else data)
        Freorder = internal.utils.fidentity if order == sys.byteorder else lambda array: array.byteswap() or array

        # Iterate through all of the members in the structure. We also check if
        # we've been asked to decode it partially. In reality, structures are
        # always partially decoded, but this flag determined whether we also
        # decode arrays partially and whether we trim incomplete fields when done.
        result, partial = {}, byteorder.get('partial', False)
        for m in internal.structure.new(identifier, 0).members:
            name, mptr, mtype, mdata = m.name, m.ptr, m.type, fields[m.name]
            dtype, dsize = (mptr.flag & mask for mask in [typemap.FF_MASK, typemap.FF_MASKSIZE])

            # Get any information about the member in case we need to extract
            # a structure identifier, string type, etc.
            opinfo = idaapi.opinfo_t()
            info = idaapi.retrieve_member_info(mptr, opinfo) if idaapi.__version__ < 7.0 else idaapi.retrieve_member_info(opinfo, mptr)

            # If it's a structure and our size matches exactly, then this is a nested dictionary.
            if info and dsize == FF_STRUCT and idaapi.get_struc_size(info.tid) == len(mdata):
                result[name] = mdata if info.tid == idaapi.BADADDR else cls.structure(info.tid, cls.structure_bytes(info.tid, mdata), order=order)

            # If it's a structure and the size is different, then this is either an array or SF_VAR structure.
            elif info and dsize == FF_STRUCT and idaapi.get_struc_size(info.tid) != len(mdata):
                sptr = idaapi.get_struc(info.tid)
                if sptr and sptr.props & SF_VAR:
                    decoded = cls.structure(info.tid, cls.structure_bytes(info.tid, mdata), order=order)

                # Take our element size, slice up the mdata, and then decode each structure as a list.
                elif sptr:
                    element = idaapi.get_struc_size(sptr)
                    sliced = cls.list(element, mdata)
                    available, used = len(mdata), sum(len(item) for item in sliced)
                    if available != used:
                        logging.warning(u"{:s}.structure({:#x}, ...{:s}) : The amount of data available ({:#x}) for decoding the \"{:s}\" member is not a multiple of the size ({:d}) of the member ({:#x}) and will result in ignoring {:+d} byte{:s} during decoding.".format('.'.join([__name__, cls.__name__]), identifier, ", {:s}".format(internal.utils.string.kwargs(byteorder)) if byteorder else '', available, name, element, mptr.id, available - used, '' if available - used == 1 else 's'))
                    iterable = cls.partial(element, mdata) if partial else sliced
                    decoded = [cls.structure(sptr.id, cls.structure_bytes(sptr.id, item), order=order, partial=partial) for item in iterable]

                # Otherwise, we leave it as-is because we can't figure out what the structure is.
                else:
                    logging.warning(u"{:s}.structure({:#x}, ...{:s}) : Unable to decode the structure for member \"{:s}\" due to its identifier ({:#x}) referencing an unknown structure.".format('.'.join([__name__, cls.__name__]), identifier, ", {:s}".format(internal.utils.string.kwargs(byteorder)) if byteorder else '', name, info.tid))
                    decoded = mdata
                result[name] = decoded

            # Just a string that we need to decode. We don't need to care about SF_VAR, or need
            # to check the string length since we use the entirely of the field to decode.
            elif info and dsize == FF_STRLIT:
                width, length, _, encoding = string.unpack(info.strtype)
                codec = string.codec(width, encoding)
                Fdecode = functools.partial(codec.decode, errors='replace') if codec else internal.utils.fthrough(bytes, len)
                ldata, strdata = mdata[:length], mdata[length:]
                prefix = cls.unsigned(Fordered(length, ldata))
                decoded, used = Fdecode(strdata)
                if length and prefix != len(decoded):
                    logging.warning(u"{:s}.structure({:#x}, ...{:s}) : The string that was decoded for field \"{:s}\" had a length ({:d}) that did not match the length stored as the prefix ({:d}).".format('.'.join([__name__, cls.__name__]), identifier, ", {:s}".format(internal.utils.string.kwargs(byteorder)) if byteorder else '', name, length, prefix))
                elif used != len(strdata):
                    logging.warning(u"{:s}.structure({:#x}, ...{:s}) : Decoding the string for field \"{:s}\" consumed a length ({:+d}) that did not match the expected length ({:+d}).".format('.'.join([__name__, cls.__name__]), identifier, ", {:s}".format(internal.utils.string.kwargs(byteorder)) if byteorder else '', name, used, len(strdata)))
                result[name] = decoded

            # Just an IEEE float that we need to decode to something that python is able to understand.
            elif dsize in {FF_FLOAT, FF_DOUBLE}:
                length = cls.length_table[dsize]
                result[name] = cls.float(Fordered(length, mdata)) if length == len(mdata) else Freorder(cls.integers(dtype, mdata)) or bytes(mdata)

            # Decoding references which could be an arbitrary size, but still need to be resolvable to an address.
            elif info and dtype & idaapi.MS_0TYPE == idaapi.FF_0OFF or dtype & idaapi.MS_1TYPE == idaapi.FF_1OFF:
                offsets = cls.array(mptr.flag, info, mdata, order=order)
                result[name] = offsets if len(offsets) > 1 else offsets[0] if offsets else bytes(mdata)

            # Otherwise, we can just decode everything using whatever flags were assigned to it.
            else:
                length = cls.length_table[dsize]
                result[name] = cls.unsigned(Fordered(length, mdata)) if length == len(mdata) else Freorder(cls.integers(mptr.flag, mdata)) or bytes(mdata)
            continue

        # Add everything else that we missed, pop out incomplete members if we
        # weren't asked to decode partially, and then return it to the caller.
        # Due to the way structure_bytes works, members with string names that
        # have values which are bytes or bytearrays are considered incomplete.
        result.update({key : fields[key] for key in fields if key not in result})
        return result if partial else {key : value for key, value in result.items() if isinstance(key, internal.types.integer) or not isinstance(value, (bytes, bytearray))}

    @classmethod
    def array(cls, flags, info, bytes, **byteorder):
        '''Return the specified `bytes` as an array of the type specified by `flags` and the ``idaapi.opinfo_t`` given by `info`.'''
        FF_STRUCT = idaapi.FF_STRUCT if hasattr(idaapi, 'FF_STRUCT') else idaapi.FF_STRU
        FF_STRLIT = idaapi.FF_STRLIT if hasattr(idaapi, 'FF_STRLIT') else idaapi.FF_ASCI

        # Extract the byteorder from the keywords and use it to generate two callables for flipping the order.
        order = cls.byteorder(**byteorder)
        Fordered = (lambda length, data: data) if order.lower() == 'big' else (lambda length, data: functools.reduce(operator.add, (item[::-1] for item in cls.list(length, data))) if data else data)
        Freorder = internal.utils.fidentity if order == sys.byteorder else lambda array: array.byteswap() or array

        # Now we need to check the opinfo and flags to figure out how to decode this.
        dtype, dsize = (flags & mask for mask in [typemap.FF_MASK, typemap.FF_MASKSIZE])
        if info and dsize == FF_STRUCT:
            # FIXME: if the structure is an SF_VAR, then this shouldn't be an array...but the
            #        user is explicitly asking for an array...so do we ignore them?
            element = idaapi.get_struc_size(info.tid)
            sliced = cls.list(element, bytes)
            available, used = len(bytes), sum(len(item) for item in sliced)
            if available != used:
                logging.warning(u"{:s}.array({:#x}, {!s}, ...{:s}) : The amount of data available ({:#x}) for decoding is not a multiple of the structure size ({:#x}) and will result in discarding {:+d} byte{:s} when attempting to decode the array.".format('.'.join([__name__, cls.__name__]), flags, "{:#x}".format(info.tid) if info else info, ", {:s}".format(internal.utils.string.kwargs(byteorder)) if byteorder else '', available, element, available - used, '' if available - used == 1 else 's'))

            # If we're being asked to decode structures partially, then we swap whatever we
            # sliced with a partial split of the bytes. This way we can partially decode as
            # much of each structure as possible when returning the list of each structure.
            partial = byteorder.get('partial', False)
            iterable = cls.partial(element, bytes) if partial else sliced
            return [cls.structure(info.tid, cls.structure_bytes(info.tid, item), order=order, partial=partial) for item in iterable]

        # Just a string that we need to decode as an array. Since we're just returning
        # an array, we don't need to decode it and can completely ignore the encoding.
        elif info and dsize == FF_STRLIT:
            width, length, _, _ = string.unpack(info.strtype)
            #codec = string.codec(width, encoding)
            #Fdecode = internal.utils.fidentity if codec is None else functools.partial(codec.decode, errors='replace')
            ldata, strdata = bytes[:length], bytes[length:]
            prefix, array = cls.unsigned(Fordered(length, ldata)), Freorder(cls.string(width, strdata))
            if length and prefix != len(array):
                logging.warning(u"{:s}.array({:#x}, {!s}, ...{:s}) : The string that was decoded had a length ({:d}) that did not match the length stored as the prefix ({:d}).".format('.'.join([__name__, cls.__name__]), flags, "{:#x}".format(info.strtype) if info else info, ", {:s}".format(internal.utils.string.kwargs(byteorder)) if byteorder else '', length, prefix))
            return array

        # Decoding references which can be of an arbitrary size, but need to be converted to an address.
        elif info and dtype & idaapi.MS_0TYPE == idaapi.FF_0OFF or dtype & idaapi.MS_1TYPE == idaapi.FF_1OFF:
            length, items = cls.length_table[dsize], cls.integers(dtype, bytes)
            reordered = Freorder(items)

            # FIXME: We should be determining the length from the reference type and figuring out the
            #        mask to apply to each value so that we can support REF_LOW8, REF_LOW16, REF_HIGH8,
            #        and REF_HIGH16, but I'm not sure about the correct way to do this. So, instead we'll
            #        use the element size (length) from the flags.. ignoring the reference type entirely.
            ritype, riflags = info.ri.flags & idaapi.REFINFO_TYPE, info.ri.flags

            # If the reference info is signed, then take our items and convert them to fit within
            # the reference type size. Unfortunately, the idaapi.as_signed function doesn't clamp
            # its integer unless it has its signed bit set, so we need to clamp that ourselves.
            if riflags & idaapi.REFINFO_SIGNEDOP and ritype in {idaapi.REF_OFF8, idaapi.REF_OFF16, idaapi.REF_OFF32, idaapi.REF_OFF64}:
                mask, signed = pow(2, 8 * length) - 1, (idaapi.as_signed(item, 8 * length) for item in reordered)
                clamped = (item if item < 0 else item & mask for item in signed)

            # Otherwise, we use the items in their unsigned form and clamp them to the reference type.
            else:
                mask = pow(2, 8 * length) - 1
                clamped = (item & mask for item in reordered)

            # Now we can translate each item according to the reference info and return it.
            ribase = 0 if info.ri.base == idaapi.BADADDR else info.ri.base
            op = functools.partial(operator.sub, ribase) if riflags & idaapi.REFINFO_SUBTRACT and ribase == info.ri.base else functools.partial(operator.add, ribase)
            translated = (op(item + info.ri.tdelta) for item in clamped)
            return [ea for ea in translated]

        # Otherwise, we can just decode everything using whatever flags we got for it.
        length = cls.length_table[dsize]
        return Freorder(cls.integers(flags, bytes))
