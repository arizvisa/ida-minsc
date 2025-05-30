"""
Interface module (internal)

This module wraps a number of features provided by IDA so that it can be
dumbed down a bit. This module is used internally and thus doesn't provide
anything that a user should use. Nonetheless, we document this for curious
individuals to attempt to understand this craziness.
"""

import six, builtins, os
import sys, logging, contextlib, hashlib, threading, weakref
import functools, operator, itertools
import collections, heapq, bisect, traceback, ctypes, math, codecs, array as _array
import fnmatch, re

import idaapi, internal, architecture
logging = logging.getLogger(__name__)

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
        if hasattr(idaapi, 'zword_flag'):
            integermap[int, 64] = getattr(idaapi, 'zword_flag')(), -1

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

        # Check if the dtype's size field (dsize) is describing a structure and verify
        # that our identifier is an integer or something that will get us a structure.
        # We have to do this explicit check because in some cases, the disassembler will
        # forget to set the FF_STRUCT flag but still assign a structure type identifier
        # to a member's opinfo_t. This way we can still pythonic-type all union members.
        if (dsize == FF_STRUCT and isinstance(typeid, internal.types.integer) and idaapi.get_struc(typeid)) or (typeid is not None and idaapi.get_struc(typeid)):
            sptr = idaapi.get_struc(typeid)
            element, variableQ = idaapi.get_struc_size(sptr), sptr.props & idaapi.SF_VAR

            # grab the structure_t and check the flags to figure out if we need to size it.
            structure = internal.structure.new(sptr.id, 0 if offset is None else offset)
            if element == size:
                return structure
            elif element:
                return (structure, size) if variableQ else [structure, size // element]
            return [structure, size]

        # Verify that we actually have the datatype in our typemap and that we can look it up.
        elif all(item not in cls.inverted for item in [dsize, dtype, (dtype, typeid), (dtype, strtype)]):
            raise internal.exceptions.InvalidTypeOrValueError(u"{:s}.dissolve({:#x}, {:s}, {:+d}, {:+#x}) : Unable to locate a pythonic type that matches the specified type ({:#x}) or identifier ({:#x}).".format('.'.join([__name__, cls.__name__]), flag, "{:#x}".format(typeid) if isinstance(typeid, internal.types.integer) else "{!s}".format(typeid), size, offset, dtype, idaapi.BADADDR if typeid is None else typeid))

        # Now that we know the datatype exists, extract the actual dtype (DT_TYPE with MS_0TYPE
        # and MS_1TYPE) and the type's dsize (DT_TYPE) from the inverted map while giving priority
        # to the dtype. This way we prioritize checking the dtype for pointers (references) first
        # (which are stored via MS_XTYPE) and only then we fall back to the dsize to find the type.
        item = cls.inverted[dtype] if dtype in cls.inverted else cls.inverted[dtype, typeid] if (dtype, typeid) in cls.inverted else cls.inverted[dtype, strtype] if (dtype, strtype) in cls.inverted else cls.inverted[dsize]

        # If it's not a tuple, then it's not a "real" type and so we can assume it's
        # a base type and we can combine it with the size to get an array out of it.
        if not isinstance(item, tuple):
            return [item, size]

        # If the item from the table has got a length, then we can just use it and
        # then fall-through. This has the side-effect of supporting string types
        # since the second part of a string tuple will always be the character width.
        elif len(item) == 2:
            t, sz = item

        # But, if our tuple contains extra information (a string) then we hack it
        # in. We do this by unpacking our width and length out of it to return.
        else:
            t, width, length = item
            reduced = item if length > 0 else (t, width) if width > 1 else t

            # XXX: The disassembler only includes the length-prefix as part of the size iff the
            #      strtype is applied to a structure, and excludes it when it is applied to an
            #      an address in the database. So, we deal with this by only calculating the
            #      string length without its prefix. Then in places where the prefix is included
            #      in the strtype (such as the database module), we use the character width to
            #      calculate the number of characters used by the length-prefix, and subtract
            #      that from the returned pythonic-type.

            #count = max(0, size - length) // width
            count = size // width
            return [reduced, count] if any([count > 1, size == 0]) else reduced if length > 0 or width > 1 else str

        # If the datatype size (sz) is not an integer, then we need to calculate
        # the size ourselves using the size parameter we were given and the element
        # size of the datatype as determined by the flags (DT_TYPE | MS_CLS).
        elsize = idaapi.get_data_elsize(idaapi.BADADDR, flag, idaapi.opinfo_t())
        if not isinstance(sz, internal.types.integer):
            res, extra = divmod(size, elsize) if elsize else (size, 0)
            count = res + 1 if extra else res
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
        FF_STRLIT = idaapi.FF_STRLIT if hasattr(idaapi, 'FF_STRLIT') else idaapi.FF_ASCI

        sz, count = None, 1

        # If we were given a pythonic-type that's a tuple, then we know that this
        # is actually an atomic type that has its flag within our typemap. We'll
        # first use the type the user gave us to find the actual table containg
        # the sizes we want to look up, and then we extract the flag and typeid
        # from the table that we determined.
        if isinstance(pythonType, ().__class__) and not isinstance(next(iter(pythonType)), (idaapi.struc_t, internal.structure.structure_t)):
            table = cls.typemap.get(builtins.next(item for item in pythonType), {})

            # First check if our pythonic type already exists in the table as a regular
            # tuple. If it is, then this is a string type and we can use it as-is.
            if pythonType in table:
                flag, typeid = table[pythonType]
                t, width, length = pythonType if len(pythonType) == 3 else pythonType + (0,)
                return flag, typeid, width + length

            # If it wasn't in the table and the length of the tuple is not 2 elements,
            # then this is an invalid type and there's nothing we can do but bail.
            elif len(pythonType) != 2:
                raise internal.exceptions.InvalidParameterError(u"{:s}.resolve({!s}) : Unable the resolve the given type ({!s}) to a corresponding native type.".format('.'.join([__name__, cls.__name__]), pythonType, pythonType))

            # Now we unpack the tuple into its basic type so we can use it to verify that
            # the type actually exists but with a negative size that we needed to absolute.
            (t, sz), count = pythonType, 1
            if (t, abs(sz)) in table:
                flag, typeid = table[t, abs(sz)]
                return flag | (idaapi.FF_SIGN if sz < 0 else 0), typeid, abs(sz)

            # Othrwise, we need to check to see if just the type itself is in our
            # table. This only occurs if the type is "unsized" which means we rely
            # on the size we were given which only occurs for alignment.
            elif t not in table:
                raise internal.exceptions.InvalidParameterError(u"{:s}.resolve({!s}) : Unable the resolve the given type ({!s}) to a corresponding native type.".format('.'.join([__name__, cls.__name__]), pythonType, pythonType))

            # Now we know that this is a valid type, we can use it to fetch the flags and
            # typeid. If the user gave us a size for this basic type, this'll get combined
            # with the count later resulting in a multiple of the basic type's size.
            flag, typeid = table[t]

        # If we were given a pythonic-type that's a list, then we know that this
        # is an array of some kind. We extract the count from the second element
        # of the list, but then we'll need to recurse into ourselves in order to
        # figure out the actual flag, type-id, and size of the type that we were
        # given by the first element of the list.
        elif isinstance(pythonType, internal.types.list):
            res, count = pythonType
            flag, info, sz = cls.resolve(res)

            # Now we need to check the flag if the type is a string, because if so
            # we'll need to adjust our size to only use the character width in its product.
            if flag & cls.FF_MASKSIZE == FF_STRLIT:
                strtype = info
                width, layout, _, _ = string.unpack(strtype)

                # Verify that our resolved array element has the exact size that we expect
                # so that we can calculate the size of the string correctly and return it.
                if sz != width + layout:
                    logging.warning(u"{:s}.resolve({!s}) : Resolving the given type ({!s}) to a string resulted in a size ({:+d}) that does not correspond to the sum of the determined width ({:d}) and length ({:d}).".format('.'.join([__name__, cls.__name__]), pythonType, pythonType, size, width, layout))
                return flag | (idaapi.FF_SIGN if sz < 0 else 0), strtype, layout + width * count

            # Otherwise we can just multiply our element width by the array length.
            tid = idaapi.BADADDR if info < 0 else info
            return flag | (idaapi.FF_SIGN if sz < 0 else 0), tid, abs(sz) * count

        # If our pythonic-type is a structure, then we extract its sptr and then
        # we can use the sptr to snag its identifier and the size of the structure.
        elif isinstance(pythonType, (idaapi.struc_t, internal.structure.structure_t)):
            sptr = pythonType if isinstance(pythonType, idaapi.struc_t) else pythonType.ptr
            flag, typeid, sz = struc_flag(), sptr.id, idaapi.get_struc_size(sptr)

        # If we got a tuple here (since we processed it earlier), then this is because
        # we're using a variable-length structure. This really means that the structure
        # is actually being scaled to the size we were given (its variable-length).
        elif isinstance(pythonType, internal.types.tuple):
            t, size = pythonType
            sptr = t.ptr if isinstance(t, internal.structure.structure_t) else t
            flag, typeid = struc_flag(), sptr.id

            # But if we're not a variable-length structure (according to the flags),
            # then the pythonic type isn't actually valid. Since this could've been
            # an accident, we avoid erroring out by correcting the size and using it.
            sz = size if sptr.props & getattr(idaapi, 'SF_VAR', 1) else idaapi.get_struc_size(sptr)

        # Anything else should be the type's default value which gets assigned for
        # both the current database and architecture. Whatever type the user gives
        # us _has_ to lead us to another table in order for it to be valid. We start
        # by using it to determine the correct table, and then from the correct table
        # we can grab the flags and type id using the None key of that table.
        elif pythonType in cls.typemap:
            table = cls.typemap[pythonType]

            # If None is not in the table, then the type-mapper was not initialized
            # which is either because we didn't receive a processor notification,
            # the database wasn't loaded, or because of something crazy and unexpected.
            if None not in table:
                info = idaapi.get_inf_structure()
                Fprocessor_name = operator.attrgetter('procname' if hasattr(info, 'procname') else 'procName')
                why = '' if info and Fprocessor_name(info) else ' due to the processor size not being detected or a database not currently open.'
                raise internal.exceptions.ItemNotFoundError(u"{:s}.resolve({!s}) : Unable the resolve the given type ({!s}) to a corresponding native type{:s}.".format('.'.join([__name__, cls.__name__]), pythonType, pythonType, why))
            flag, typeid = table[None]

            # Construct an opinfo_t with the type-id that was returned, and then
            # calculate the correct size for the value returned by our table.
            opinfo, typeid = idaapi.opinfo_t(), idaapi.BADADDR if typeid < 0 else typeid
            opinfo.tid = typeid
            return flag, typeid, idaapi.get_data_elsize(idaapi.BADADDR, flag, opinfo)

        # This is our catch-all so that we can compain about it to the user.
        else:
            raise internal.exceptions.InvalidParameterError(u"{:s}.resolve({!s}) : Unable the resolve the given type ({!s}) to a corresponding native type.".format('.'.join([__name__, cls.__name__]), pythonType, pythonType))

        # If we fell-through, we should have the flags, type identifier, and the
        # total size that IDAPython needs when describing a type. If we received
        # a count, then our resulting size is the product of the count and the
        # basic size. We also check our basic size for negativity so that we can
        # update the flags with FF_SIGN if that's what the user intended.
        typeid = idaapi.BADADDR if typeid < 0 else typeid
        return flag | (idaapi.FF_SIGN if sz < 0 else 0), typeid, abs(sz) * count

    @classmethod
    def update_refinfo(cls, identifier, flag):
        '''This updates the refinfo for the given `identifer` according to the provided `flag`.'''
        return address.update_refinfo(identifier, flag)

    @classmethod
    def element(cls, pythonType):
        '''Return the element size of the provided `pythonType` discarding the array component if one was provided.'''

        # If we were given a list (for an array), then unpack it since
        # its length is entirely irrelevant to us.
        if isinstance(pythonType, internal.types.list):
            element, _ = [item for item in itertools.chain(pythonType, 2 * [0])][:2]
            return cls.element(element) if len(pythonType) == 2 else 0

        # If it's a tuple, then we can just unpack our size from the type and then return it.
        if isinstance(pythonType, internal.types.tuple):
            _, size, _ = [item for item in itertools.chain(pythonType, 3 * [0])][:3]
            return max(0, size) if isinstance(size, internal.types.integer) and len(pythonType) in {2, 3} else 0

        # If it's one of our structure types, then we can extract their sptr and use it.
        if isinstance(pythonType, (idaapi.struc_t, internal.structure.structure_t)):
            sptr = pythonType if isinstance(pythonType, idaapi.struc_t) else pythonType.ptr
            return idaapi.get_struc_size(sptr)

        # Otherwise, we need to do a default type lookup to get the number of bytes.
        opinfo, table = idaapi.opinfo_t(), cls.typemap.get(pythonType, {}) if getattr(pythonType, '__hash__', None) else {}
        flag, typeid = table.get(None, (-1, -1))
        opinfo.tid = idaapi.BADADDR if typeid < 0 else typeid
        return idaapi.get_data_elsize(idaapi.BADADDR, flag, opinfo) if None in table else 0

    @classmethod
    def size(cls, pythonType):
        '''Return the total expected size of the provided `pythonType`.'''

        # If we have a list, then calculate the array size using the element type and length.
        if isinstance(pythonType, internal.types.list):
            element, unchecked = [item for item in itertools.chain(pythonType, 2 * [0])][:2]
            length = max(0, unchecked) if isinstance(unchecked, internal.types.integer) else 0
            return cls.size(element) * length if len(pythonType) == 2 else 0

        # If it's a tuple, then we can unpack our size from the type and return it.
        if isinstance(pythonType, internal.types.tuple):
            _, size, _ = [item for item in itertools.chain(pythonType, 3 * [0])][:3]
            return max(0, size) if isinstance(size, internal.types.integer) and len(pythonType) in {2, 3} else 0

        # If it's not a tuple, then it might be a structure to snag the size from.
        if isinstance(pythonType, (idaapi.struc_t, internal.structure.structure_t)):
            sptr = pythonType if isinstance(pythonType, idaapi.struc_t) else pythonType.ptr
            return idaapi.get_struc_size(sptr)

        # If it wasn't either, then we need to do a default type lookup for the size.
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

    @classmethod
    def default(cls):
        '''Return the default string type configured for the current database.'''
        return database.strtype()

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
    def __init__(self):
        self.__cache, self.__traceback = {}, {}

        # cache for the scope that is allocated for each target. we call this "scope",
        # but really it's the three closures that capture the scope for each target.
        self.__target_scopes = {}

        # Set containing the targets that are currently disabled.
        self.__disabled = {item for item in []}

    def __iter__(self):
        '''Iterate through each target that is currently attached to this object.'''
        for target in self.__cache:
            yield target
        return

    def __contains__(self, target):
        '''Return whether the specified `target` is currently attached to this object.'''
        return target in self.__cache

    def __len__(self):
        '''Return the number of targets that are currently attached to this object.'''
        return len(self.__cache)

    def __formatter__(self, target):
        raise NotImplementedError

    def close(self):
        '''Disconnect from all of the targets that are currently attached'''
        res, items = True, {item for item in self.__cache}

        # Simply detach every available target one-by-one.
        for target in items:
            ok = self.detach(target)
            if ok:
                self.__cache.pop(target)
            else:
                logging.warning(u"{:s}.close() : Error while attempting to detach from the specified target {:s}.".format('.'.join([__name__, self.__class__.__name__]), self.__formatter__(target)))
            res = res and ok
        return res

    @property
    def available(self):
        '''Return all of the attached targets that can be either enabled or disabled.'''

        # This property is intended to be part of the public api and
        # thus it can reimplemented by one if considered necessary.

        return {item for item in self.__cache}

    def list(self, *pattern):
        """List all of the targets that are available along with a description.

        If a glob is passed as a `pattern`, then only the targets matching said
        pattern will be listed.
        """
        Fmatch = re.compile(fnmatch.translate(*pattern), re.IGNORECASE).match if pattern else internal.utils.fconstant(True)

        # This property is intended to be part of the public api and
        # thus it can reimplemented by one if considered necessary.

        targets = sorted(self.available)
        formatted = {item : "{!s}:".format(item) for item in targets}
        length = max(map(len, formatted.values())) if formatted else 0

        if formatted:
            for item in targets:
                item_description, item_formatted = formatted[item], self.__formatter__(item)
                if any(Fmatch(string) for string in [item_description, item_formatted]):
                    six.print_(u"{:<{:d}s} {:s}".format(item_description, length, item_formatted))
                continue
            return
        six.print_(u"There are no available targets.")

    @property
    def disabled(self):
        '''Return all of the attached targets that are currently disabled.'''
        return {item for item in self.__disabled}
    @property
    def enabled(self):
        '''Return all of the attached targets that are currently enabled.'''
        return {item for item in self.__cache} - {item for item in self.__disabled}

    # Extract the parameters from a function. This is just a wrapper around
    # utils.pycompat.function.arguments so that we can extract the names.
    @classmethod
    def __repr_parameters__(cls, func):
        '''Yield each parameter from the function `func` formatted as a readable string.'''
        args, defaults, (star, starstar) = internal.utils.pycompat.function.arguments(func)
        for item in args:
            yield "{:s}={!s}".format(item, defaults[item]) if item in defaults else item
        if star:
            yield "*{:s}".format(star)
        if starstar:
            yield "**{:s}".format(starstar)
        return

    @classmethod
    def __repr_callable__(cls, object):
        '''Return the callable in `object` as a readable string and tuple containing its named parameters.'''
        parameters, pycompat = cls.__repr_parameters__, internal.utils.pycompat

        # If a method is passed to us, then we need to extract all
        # of the relevant components that describe it.
        if isinstance(object, (internal.types.method, internal.types.descriptor)):
            func = pycompat.method.function(object)
            iterable = parameters(func)
            None if isinstance(object, internal.types.staticmethod) else next(iterable)
            return pycompat.fullname(object), tuple(iterable)

        # If our object is a function-type, then it's easy to grab.
        elif isinstance(object, internal.types.function):
            iterable = parameters(object)
            return pycompat.fullname(object), tuple(iterable)

        # If it's still callable, then this is likely a class.
        elif callable(object):
            symbols = object.__dict__
            cons = symbols.get('__init__', symbols.get('__new__', None))
            iterable = iter(parameters(cons) if cons else [])
            next(iterable, None)
            return pycompat.fullname(object), tuple(iterable)

        # Otherwise, we have no idea what it is...
        return "{!r}".format(object), None

    @classmethod
    def __repr_object__(cls, object):
        '''Return the specified `object` as a readable and user-friendly string.'''
        string_t, integer_t = internal.types.string, internal.types.integer
        callable_t = internal.types.function, internal.types.method, staticmethod, classmethod

        # check if our cached object exists and use it if it does.
        if hasattr(cls, '__describe_object__'):
            object_t, describe = object.__class__, cls.__describe_object__
            if object_t in describe:
                format = describe[object_t]
                return format(object)
            elif callable(object) and isinstance(object, callable_t):
                format = describe[callable]
                return format(object)
            elif isinstance(object, internal.types.type) and issubclass(object_t, internal.types.type):
                iterable = itertools.chain([] if getattr(object, '__module__', None) is None else [object.__module__], [object.__name__])
                return "{!s}".format('.'.join(iterable))
            return "{!r}".format(object)

        # otherwise, we'll need to generate some dicts for formatting.
        describe = {}

        # we'll need a way to represent strings and integers (atomics).
        [describe.setdefault(type, "{!r}".format) for type in itertools.chain(string_t if isinstance(string_t, internal.types.unordered) else [string_t])]
        [describe.setdefault(type, "{:#x}".format) for type in itertools.chain(integer_t if isinstance(integer_t, internal.types.unordered) else [integer_t])]

        # then we'll do any callables. these aren't actually a type, but we
        # stash them in our dictionary as "callable" anyways.
        def format_callable(object):
            name, args = cls.__repr_callable__(object)
            return name if args is None else "{:s}({:s})".format(name, ', '.join(args))
        describe[callable] = format_callable

        # now we'll need to do the container types. these are pretty much always
        # treated as a set, so we'll make sure to format them as a set. we also
        # need a function that sorts as much as possible to keep the sortable
        # elements close to the beginning of the container.
        def sortable(iterable):
            items = [item for item in iterable]
            sortable, remaining = [], []
            for item in items:
                try: sorted([0, item])
                except: remaining.append(item)
                else: sortable.append(item)
            iterable = itertools.chain(sorted(sortable), remaining)
            return [item for item in iterable]

        callable_t = internal.types.function, internal.types.method, staticmethod, classmethod
        def format_elements(iterable):
            res, items = [], [item for item in iterable]
            for element in sortable(iterable):
                element_t = element.__class__
                if element_t in describe:
                    format = describe[element_t]
                    res.append(format(element))
                elif callable(element) and isinstance(element, callable_t):
                    format = describe[callable]
                    res.append(format(element))
                elif isinstance(element, internal.types.type) and issubclass(element_t, internal.types.type):
                    iterable = itertools.chain([] if getattr(element, '__module__', None) is None else [element.__module__], [element.__name__])
                    res.append("{!s}".format('.'.join(iterable)))
                else:
                    res.append("{!r}".format(element))
                continue
            return res

        # XXX: we're treating dictionaries as sets here, because users of this
        #      method really shouldn't need to render the values for each key.
        formatters = {
            internal.types.set: "{{{!s}}}".format,
            internal.types.dictionary: "{{{!s}}}".format,
            internal.types.list: "[{!s}]".format,
        }

        for type in [internal.types.set, internal.types.list, internal.types.dictionary]:
            format = formatters[type]
            describe[type] = lambda item: format(', '.join(format_elements(item)))

        # assign our lookup dictionary as a property of the class, and then
        # recurse in order to do what the user asked us to do.
        cls.__describe_object__ = describe
        return cls.__repr_object__(object)

    def __repr__(self):
        cls, enabled = self.__class__, {item for item in self.__cache} - {item for item in self.__disabled}

        # Unpack a prioritytuple into its components so we can describe it.
        def repr_prioritytuple(tuple):
            priority, callable = tuple
            name, args = self.__repr_callable__(callable)
            return priority, name, args

        # If there aren't any targets available, then return immediately.
        if not self.__cache:
            return '\n'.join(["{!s}".format(cls), "...No targets are being used...".format(cls)])

        alignment_enabled = max(len(self.__formatter__(target)) for target in enabled) if enabled else 0
        alignment_disabled = max(len("{:s} (disabled)".format(self.__formatter__(target))) for target in self.__disabled) if self.__disabled else 0
        res = ["{!s}".format(cls)]

        # First gather all our enabled hooks.
        for target in sorted(enabled):
            _, queue_ = self.__cache[target]
            hooks = sorted([(priority, callable) for priority, callable in queue_], key=operator.itemgetter(0))
            items = ["{description:s}[{:+d}]".format(priority, description=name if args is None else "{:s}({:s})".format(name, ', '.join(args))) for priority, name, args in map(repr_prioritytuple, hooks)]
            res.append("{:<{:d}s} : {!s}".format(self.__formatter__(target), alignment_enabled, ' '.join(items) if items else '...nothing attached...'))

        # Now we can append all the disabled ones.
        for target in sorted(self.__disabled):
            _, queue_ = self.__cache[target]
            hooks = sorted([(priority, callable) for priority, callable in queue_], key=operator.itemgetter(0))
            items = ["{description:s}[{:+d}]".format(priority, description=name if args is None else "{:s}({:s})".format(name, ', '.join(args))) for priority, name, args in map(repr_prioritytuple, hooks)]
            res.append("{:<{:d}s} : {!s}".format("{:s} (disabled)".format(self.__formatter__(target)), alignment_disabled, ' '.join(items) if items else '...nothing attached...'))

        # And then return it to the caller.
        return '\n'.join(res)

    def enable(self, target):
        '''Enable any callables for the specified `target` that have been previously disabled.'''
        cls = self.__class__
        if target not in self.__cache:
            logging.fatal(u"{:s}.enable({!r}) : The requested target {:s} is not attached. {:s}".format('.'.join([__name__, cls.__name__]), target, self.__formatter__(target), "Currently disabled targets are: {:s}".format(', '.join(map(self.__formatter__, self.__disabled))) if self.__disabled else 'There are no disabled targets that may be enabled.'))
            return False
        if target not in self.__disabled:
            logging.fatal(u"{:s}.enable({!r}) : The requested target {:s} is not disabled. {:s}".format('.'.join([__name__, cls.__name__]), target, self.__formatter__(target), "Currently disabled targets are: {:s}".format(', '.join(map(self.__formatter__, self.__disabled))) if self.__disabled else 'There are no disabled targets that may be enabled.'))
            return False

        # Always explicitly do what we're told...
        self.__disabled.discard(target)

        # But if there were no entries in the cache, then warn the user about it.
        _, queue_ = self.__cache[target]
        if not queue_:
            logging.warning(u"{:s}.enable({!r}) : The requested target {:s} does not have any callables in its priority queue to enable.".format('.'.join([__name__, cls.__name__]), target, self.__formatter__(target)))
            return True
        return True

    def disable(self, target):
        '''Disable execution of all the callables for the specified `target`.'''
        cls, enabled = self.__class__, {item for item in self.__cache} - self.__disabled
        if target not in self.__cache:
            logging.fatal(u"{:s}.disable({!r}) : The requested target {:s} is not attached. {:s}".format('.'.join([__name__, cls.__name__]), target, self.__formatter__(target), "Currently enabled targets are: {:s}".format(', '.join(map(self.__formatter__, enabled))) if enabled else 'All targets have already been disabled.' if self.__disabled else 'There are no currently attached targets to disable.'))
            return False
        if target in self.__disabled:
            logging.warning(u"{:s}.disable({!r}) : The requested target {:s} has already been disabled. {:s}".format('.'.join([__name__, cls.__name__]), target, self.__formatter__(target), "Currently enabled targets are: {:s}".format(', '.join(map(self.__formatter__, enabled))) if enabled else 'All targets have already been disabled.'))
            return False
        self.__disabled.add(target)
        return True

    def add(self, target, callable, priority):
        '''Add the `callable` to the queue for the specified `target` with the given `priority`.'''
        if not builtins.callable(callable):
            cls, format = self.__class__, "{:+d}".format if isinstance(priority, internal.types.integer) else "{!r}".format
            raise TypeError(u"{:s}.add({!r}, {!s}, priority={!r}) : Refusing to add a non-callable ({!s}) for the requested target {:s} with the given priority ({!r}).".format('.'.join([__name__, cls.__name__]), target, callable, priority, callable, self.__formatter__(target), format(priority)))
        elif not isinstance(priority, internal.types.integer):
            cls, format = self.__class__, "{:+d}".format if isinstance(priority, internal.types.integer) else "{!r}".format
            raise TypeError(u"{:s}.add({!r}, {!s}, priority={!r}) : Refusing to add a callable ({:s}) for the requested target {:s} with a non-integer priority ({!r}).".format('.'.join([__name__, cls.__name__]), target, callable, priority, internal.utils.pycompat.fullname(callable), self.__formatter__(target), format(priority)))

        # grab the mutex for the target queue that we're going to add something to.
        mutex, queue_ = self.__cache.setdefault(target, (threading.Lock(), []))
        with mutex:
            queue = queue_

            # remove any already existing instances of the callable and priority to be added.
            indices = {index for index, (order, item) in enumerate(queue) if order == priority and item == callable}
            if indices:
                cls, items = self.__class__, [item for item in map("{:d}".format, sorted(indices))]
                iterable = itertools.chain(items[:-1], ["and {:s}".format(*items[-1:])]) if len(items) > 2 else [' and '.join(items)] if len(items) == 2 else items
                logging.warning(u"{:s}.add({!r}, {!s}, priority={:+d}) : Removing duplicate instance{:s} of callable ({!s}) with priority {:+d} from target {:s} at ind{:s} {:s}.".format('.'.join([__name__, cls.__name__]), target, callable, priority, '' if len(indices) ==1 else 's', callable, priority, self.__formatter__(target), 'ex' if len(indices) == 1 else 'ices', ', '.join(iterable)))
                queue[:] = [priority_tuple for index, priority_tuple in enumerate(queue) if index not in indices]

            # collect any other priorities in the queue that the same callable might
            # be being used for, so that we inform the user if it wasn't intentnional.
            duplicate_priorities = {order for order, item in queue if item == callable}

            # add the callable to our priority queue
            heapq.heappush(queue, internal.utils.priority_tuple(priority, callable))

            # preserve a backtrace so we can track where our callable is at
            self.__traceback[(target, callable)] = traceback.extract_stack()[:-1]

        # if there were any duplicated instances of the callable, then log it
        # with a warning just in case it might've actually been intentional.
        if duplicate_priorities:
            cls, items = self.__class__, [item for item in map("{:+d}".format, sorted(duplicate_priorities))]
            iterable = itertools.chain(items[:-1], ["and {:s}".format(*items[-1:])]) if len(items) > 2 else [' and '.join(items)] if len(items) == 2 else items
            logging.warning(u"{:s}.add({!r}, {!s}, priority={:+d}) : The newly added callable ({!s}) for the target {:s} is also attached at priorit{:s} {:s}.".format('.'.join([__name__, cls.__name__]), target, callable, priority, callable, self.__formatter__(target), 'y' if len(duplicate_priorities) == 1 else 'ies', ', '.join(iterable)))
        return True

    def get(self, target):
        '''Return all of the callables that are attached to the specified `target`.'''
        if target not in self.__cache:
            cls = self.__class__
            raise NameError(u"{:s}.get({!r}) : The requested target {:s} is not attached. {:s}".format('.'.join([__name__, cls.__name__]), target, self.__formatter__(target), "Currently attached targets are: {:s}".format(', '.join(map(self.__formatter__, self.__cache))) if self.__cache else 'There are no currently attached targets to get from.'))

        # Return the callables attached to the specified target.
        mutex, queue_ = self.__cache[target]
        with mutex:
            result = tuple(callable for _, callable in queue_)
        return result

    def pop(self, target, index=-1):
        '''Pop the item at the specified `index` from the given `target`.'''
        if target not in self.__cache:
            cls, format = self.__class__, "{:d}".format if isinstance(index, internal.types.integer) else "{!r}".format
            raise NameError(u"{:s}.pop({!r}, {:d}) : The requested target {:s} is not attached. Currently attached targets are {:s}.".format('.'.join([__name__, cls.__name__]), target, format(index), self.__formatter__(target), "Currently attached targets are: {:s}".format(', '.join(map(self.__formatter__, self.__cache))) if self.__cache else 'There are no targets currently attached to pop from.'))
        state = []

        # Snapshot our current queue for the specified target.
        mutex, queue_ = self.__cache[target]
        with mutex:
            queue = queue_

            # Iterate through the cache for the specified target and collect
            # each callable so we can figure out which one to remove.
            for (priority, F) in queue:
                state.append((priority, F))

            # Pop off the result the user requested, and then combine our
            # state back into the cache we took it from.
            item = state.pop(index)
            if state:
                queue[:] = [internal.utils.priority_tuple(*item) for item in state]

            # Otherwise our target will need to be emptied.
            else:
                queue[:] = []

            # Now we can return whatever was removed, and clear it from the traceback.
            priority, result = item
            self.__traceback.pop((target, result))

        return result

    def discard(self, target, callable):
        '''Discard the `callable` from our priority queue for the specified `target`.'''
        if target not in self.__cache:
            return False
        state = []

        # Snapshot our current queue for the specified target.
        mutex, queue_ = self.__cache[target]
        with mutex:
            queue = queue_

            # Filter through our cache for the specified target, and collect
            # each callable except for the one the user provided.
            found = 0
            for index, (priority, F) in enumerate(queue):
                if F == callable:
                    found += 1
                    continue
                state.append((priority, F))

            # If we aggregated some items, then replace our cache with everything
            # except for the item the user discarded.
            if state:
                queue[:] = [internal.utils.priority_tuple(*item) for item in state]

            # Otherwise we found nothing and we should just empty the target.
            else:
                queue[:] = []

            # Silently remove the callable out of the traceback.
            self.__traceback.pop((target, callable), None)

        return True if found else False

    def remove(self, target, priority):
        '''Remove the first callable from the specified `target` that has the provided `priority`.'''
        if target not in self.__cache:
            cls, format = self.__class__, "{:+d}".format if isinstance(priority, internal.types.integer) else "{!r}".format
            raise NameError(u"{:s}.remove({!r}, {:s}) : The requested target {:s} is not attached. {:s}".format('.'.join([__name__, cls.__name__]), target, format(priority), self.__formatter__(target), "Currently attached targets are: {:s}".format(', '.join(map(self.__formatter__, self.__cache))) if self.__cache else 'There are no targets currently attached to remove from.'))
        state, table = [], {}

        # First we'll need to snapshot the queue for our current target.
        mutex, queue_ = self.__cache[target]
        with mutex:
            queue = queue_

            # Iterate through our cache for the specified target and save
            # both the state and the index of every single priority.
            for index, (prio, F) in enumerate(queue):
                state.append((prio, F))
                table.setdefault(prio, []).append(index)

            # Before we do anything, we need to ping the priority we're searching for
            # in the table and then we grab the first index for the given priority.
            if priority not in table:
                cls, format = self.__class__, "{:+d}".format if isinstance(priority, internal.types.integer) else "{!r}".format
                raise internal.exceptions.ItemNotFoundError(u"{:s}.remove({!r}, {:s}) : Unable to locate a callable with the specific priority ({:s}).".format('.'.join([__name__, cls.__name__]), target, format(priority), format(priority)))
            index = table[priority].pop(0)

            # We now can pop the index directly out of the state. Afterwards, we
            # need to shove our state back into the cache for the target.
            item = state.pop(index)
            if state:
                queue[:] = [internal.utils.priority_tuple(*item) for item in state]

            # If our state is empty, then we go ahead and empty the target.
            else:
                queue[:] = []

            # We have an item that we can now return once we clear its traceback.
            priority, result = item
            self.__traceback.pop((target, result), None)

        return result

    def empty(self, target):
        '''Iterate through the queue for the specified `target` safely discarding each callable before yielding it.'''
        if target not in self.__cache:
            cls = self.__class__
            raise NameError(u"{:s}.empty({!r}) : The requested target {:s} is not attached. Currently attached targets are {:s}.".format('.'.join([__name__, cls.__name__]), target, self.__formatter__(target), "Currently attached targets are: {:s}".format(', '.join(map(self.__formatter__, self.__cache))) if self.__cache else 'There are no targets currently attached to empty.'))

        # Grab the queue we're supposed to empty for the specified target.
        mutex, queue_ = self.__cache[target]
        with mutex:
            queue = queue_

            # Start at the head, remove each element from the queue, and
            # capture the callable we removed. This way we can yield it.
            items = []
            while queue:
                priority, callable = queue.pop(0)
                backtrace = self.__traceback.pop((target, callable), None)
                items.append((callable, backtrace))

            # XXX: At the current moment, we always succeed (hence our item always being set as
            #      True). In the future, though, there could be situations where we're unable to
            #      remove the callable due to it being still attached to some resource that the
            #      disassembler refused to release it from.
            result = [(True, callable) for callable, backtrace in items]

        # And we can yield them to the caller in the order they were removed.
        for ok, callable in result:
            yield ok, callable
        return

    def attach(self, target):
        """Return a tuple containing a count and a set of closures for the given `target` that are used to control the execution of the attached callables.

        Each closure is intended to be attached to whatever is being hooked by each
        callable. The first closure is used to initialize execution and is intended
        to be executed first. The second closure will execute each individual callable,
        and the third closure will reset execution so that they can be called again.

        This method is intended to be called as a supermethod for the specified `target`.
        """
        cls = self.__class__

        # First grab the specified target and count how many callables
        # that it needs to execute in order for it to work properly.
        cached = self.__target_scopes.get(target)

        mutex, queue_ = self.__cache.setdefault(target, (threading.Lock(), []))
        with mutex:
            count = len(queue_)

        # If this target has had its scope already created, then we can return
        # return the count and the closures that use it instead of recreating them.
        if cached is not None:
            iterable = (ref() for ref in cached.references)
            return count, tuple(iterable)

        ## Begin the scope for each of the closures returned by this method.
        class Signal(object):
            '''This class is just for creating signals to track the beginning and ending of a coroutine's execution.'''
            __slots__ = ['__name__']
            def __init__(self, name):
                self.__name__ = name
            def __repr__(self):
                cls = self.__class__
                return '.'.join([item.__name__ for item in [cls, self]])

        class State(object):
            '''This class is for maintaining any state shared by the closures defined within this function.'''
            __slots__ = ['BEGIN', 'END', 'running_queue', 'references']

        # States that are used by the coroutines to manage the scope of the
        # callables that are attached to a target. These are yielded to the
        # closures in order to track when things are being reset or torn down.
        State.BEGIN, State.END = (Signal(name) for name in ['BEGIN', 'END'])

        # This is just a weakly-referenced cache for the closures that we generate.
        State.references = []

        # This is a queue the maintains the coroutines that have been explciitly started. Everytime
        # the "start" closure is executed, the coroutine that processes the target's priority queue
        # gets appended to this. This is so we can support recursion when dispatching to a callable.
        State.running_queue = []

        ## Utilities for dealing with parameters like comparisons and formatting them so that they're readable.
        def format_parameters(*args, **kwargs):
            '''Return the provided parameters formatted as a string.'''
            ordered = ', '.join(map("{!r}".format, args))
            keywords = ["{:s}={!r}".format(key, kwargs[key]) for key in sorted(kwargs)]
            return "{:s}, {:s}".format(ordered, ', '.join(keywords)) if kwargs else ordered

        def same_parameters(parameters_old, parameters_new):
            '''Compare the tuple of `parameters_old` with the tuple of `parameters_new`.'''
            old_args, old_kwargs = parameters_old
            new_args, new_kwargs = parameters_new
            old_iterable = itertools.chain([item for item in old_args], [(key, old_kwargs[value]) for key in sorted(old_kwargs)])
            new_iterable = itertools.chain([item for item in new_args], [(key, new_kwargs[value]) for key in sorted(new_kwargs)])
            old, new = ([item for item in iterable] for iterable in [old_iterable, new_iterable])
            return len(old) == len(new) and all(oldarg == newarg for oldarg, newarg in zip(old, new))

        ## Coroutine-specific utilities for determining their current execution state.
        def is_coroutine_stopped(coro):
            '''Return whether the coroutine specified by `coro` has completed execution.'''
            return coro.gi_frame is None

        def is_coroutine_running(coro):
            '''Return whether the coroutine specified by `coro` is actively running.'''
            return coro.gi_running

        def is_coroutine_started_py2(coro):
            '''Return whether the coroutine specified by `coro` has already been started.'''
            if coro.gi_frame is None:
                return False
            return coro.gi_running or coro.gi_frame.f_lasti > -1

        def is_coroutine_started_py3(coro):
            '''Return whether the coroutine specified by `coro` has already been started.'''
            if coro.gi_frame is None:
                return False
            return coro.gi_running or getattr(coro, 'gi_suspended', coro.gi_frame.f_lasti > 0)

        is_coroutine_started = is_coroutine_started_py2 if sys.version_info.major < 3 else is_coroutine_started_py3

        ## The actual coroutines that process the contents of a queue. There is one
        ## for when a target is enabled, and another for when the target is disabled.

        def coroutine_when_enabled(hookq):
            '''This coroutine is responsible for actually processing the contents of the `hookq` that is given.'''
            logging.debug(u"{:s}.coroutine_when_enabled({!r}) : Coroutine for the target {:s} has been started with queue containing {:d} item{:s}.".format('.'.join([__name__, self.__class__.__name__]), target, self.__formatter__(target), len(hookq), '' if len(hookq) == 1 else 's'))
            counter, old_args, old_kwargs, parameters = 0, [], {}, (yield State.BEGIN)
            for index, (priority, callable) in enumerate(hookq):
                args, kwargs = parameters
                parameters_description = format_parameters(*args, **kwargs)

                # unpack the parameters and compare them with whatever we received previously. this way we
                # can issue a warning if the parameters have changed between the execution of each hook.
                if index > 0 and not same_parameters((old_args, old_kwargs), parameters):
                    logging.debug(u"{:s}.coroutine_when_enabled({!r}) : Parameters received for the target {:s} ({:+d}) have unexpectedly changed from ({:s}) to ({:s}) during execution of {:s} ({:s}).".format('.'.join([__name__, self.__class__.__name__]), target, self.__formatter__(target), priority, parameters_description, format_parameters(*old_args, **old_kwargs), internal.utils.pycompat.fullname(callable), "{:s}:{:d}".format(*internal.utils.pycompat.file(callable))))

                # execute the callable with the parameters we were given.
                logging.info(u"{:s}.coroutine_when_enabled({!r}) : Dispatching parameters ({:s}) for target {:s} ({:+d}) to callable {:d} of {:d} at {:s} ({:s}).".format('.'.join([__name__, self.__class__.__name__]), target, parameters_description, self.__formatter__(target), priority, 1 + index, len(hookq), internal.utils.pycompat.fullname(callable), "{:s}:{:d}".format(*internal.utils.pycompat.file(callable))))
                try:
                    result = callable(*args, **kwargs)

                # if we caught an exception, then inform the user about it and stop processing our queue
                except:
                    backtrace = traceback.format_list(self.__traceback[target, callable])
                    current = str().join(traceback.format_exception(*sys.exc_info()))

                    # log a backtrace and exit our loop since we caught an exception that interrupted
                    # our execution here. technically, we've stopped walking through our priority queue.
                    format = functools.partial(u"{:s}.coroutine_when_enabled({!r}) : {:s}".format, '.'.join([__name__, cls.__name__]), target)
                    logging.fatal(format(u"Target {:s} for {:s} with priority {:+d} raised an exception while executing with parameters ({:s}).".format(self.__formatter__(target), internal.utils.pycompat.fullname(callable), priority, parameters_description)))
                    logging.warning(format(u"Traceback for {:s} was attached at:".format(self.__formatter__(target))))
                    [ logging.warning(format(item)) for item in str().join(backtrace).split('\n') ]
                    [ logging.warning(format(item)) for item in current.split('\n') ]
                    break

                # save the parameters we successfully processed, so that we can verify them next iteration.
                counter, old_args, old_kwargs, parameters = counter + 1, args, kwargs, (yield result)

            # now we need to spin in a loop indefinitely until we're explicitly closed.
            logging.debug(u"{:s}.coroutine_when_enabled({!r}) : Coroutine for the target {:s} has completed executing {:d} of {:d} item{:s} and is waiting for termination.".format('.'.join([__name__, self.__class__.__name__]), target, self.__formatter__(target), counter, len(hookq), '' if len(hookq) == 1 else 's'))
            try:
                result = State.END
                while True:
                    parameters = (yield result)
                    args, kwargs = parameters
                    logging.info(u"{:s}.coroutine_when_enabled({!r}) : Coroutine for the target {:s} has received parameters ({:s}) and is still waiting for termination.".format('.'.join([__name__, self.__class__.__name__]), target, self.__formatter__(target), format_parameters(*args, **kwargs)))

                    # verify that our parameters haven't changed so that we can warn the user about it.
                    if not same_parameters((old_args, old_kwargs), parameters):
                        logging.debug(u"{:s}.coroutine_when_enabled({!r}) : Parameters received for the target {:s} have unexpectedly changed from ({:s}) to ({:s}) while waiting for termination.".format('.'.join([__name__, self.__class__.__name__]), target, self.__formatter__(target), parameters_description, format_parameters(*args, **kwargs)))
                    continue

            # at this point, we should be able to clean up everything if anything.
            except GeneratorExit:
                logging.debug(u"{:s}.coroutine_when_enabled({!r}) : Coroutine for the target {:s} has completed execution of its queue ({:d} of {:d} item{:s}) and was properly closed.".format('.'.join([__name__, self.__class__.__name__]), target, self.__formatter__(target), counter, len(hookq), '' if len(hookq) == 1 else 's'))
            return

        def coroutine_when_disabled(hookq):
            '''This coroutine is only used to process callables when the target has been disabled.'''
            logging.debug(u"{:s}.coroutine_when_disabled({!r}) : Coroutine for the disabled target {:s} has been started with queue containing {:d} item{:s}.".format('.'.join([__name__, self.__class__.__name__]), target, self.__formatter__(target), len(hookq), '' if len(hookq) == 1 else 's'))
            parameters = (yield State.BEGIN)

            # capture our parameters and log them for the sake of debugging.
            args, kwargs = parameters
            parameters_description = format_parameters(*args, **kwargs)
            logging.debug(u"{:s}.coroutine_when_disabled({!r}) : Coroutine for the disabled target {:s} has been started and is waiting for termination.".format('.'.join([__name__, self.__class__.__name__]), target, self.__formatter__(target)))

            # spin indefinitely, always returning the END state.
            try:
                result = State.END
                while True:
                    new_parameters = (yield result)
                    args, kwargs = new_parameters
                    logging.debug(u"{:s}.coroutine_when_disabled({!r}) : Coroutine for the disabled target {:s} has received parameters ({:s}) and is still waiting for termination.".format('.'.join([__name__, self.__class__.__name__]), target, self.__formatter__(target), format_parameters(*args, **kwargs)))

                    # for sanity, we'll keep checking our parameters so we can warn the user if they changed.
                    if not same_parameters(parameters, new_parameters):
                        logging.info(u"{:s}.coroutine_when_disabled({!r}) : Parameters received for the disabled target {:s} have unexpectedly changed from ({:s}) to ({:s}) while waiting for termination.".format('.'.join([__name__, self.__class__.__name__]), target, self.__formatter__(target), parameters_description, format_parameters(*args, **kwargs)))
                    continue

            # nothing left to do here but leave.
            except GeneratorExit:
                logging.debug(u"{:s}.coroutine_when_disabled({!r}) : Coroutine for the disabled target {:s} was properly closed by the caller.".format('.'.join([__name__, self.__class__.__name__]), target, self.__formatter__(target)))
            return

        ## These are the closures that manage the scope of one of the prior 2 coroutines.

        # This first one is responsible for creating and initializing the coroutine which
        # is what actually gets everything started.
        def closure_start(*args, **kwargs):
            '''This closure is responsible for initializing execution of the coroutine and is the very-first callable that needs to be attached.'''
            parameters = args, kwargs
            parameters_description = format_parameters(*args, **kwargs)

            # If we're being called, then we need to first snapshot the list of callables
            # to execute. We sort them by priority so that we can hand them to a new coroutine.
            if target in self.__cache:
                mutex, queue_ = self.__cache[target]
                with mutex: queue = queue_[:]
                hookq = heapq.nsmallest(len(queue), queue, key=operator.attrgetter('priority'))

            else:
                hookq = []

            # Now we can instantiate the coroutine using our sorted priority queue (hookq). If the
            # target has been disabled, we use "coroutine_when_disabled" instead to maintain state.
            logging.debug(u"{:s}.closure_start({!r}) : Coroutine #{:d} for the {:s}target {:s} was created and will be started with {:d} item{:s} to execute.".format('.'.join([__name__, self.__class__.__name__]), target, 1 + len(State.running_queue), 'disabled ' if target in self.__disabled else '', self.__formatter__(target), len(hookq), '' if len(hookq) == 1 else 's'))
            coro = coroutine_when_enabled(hookq) if target in self.__cache and target not in self.__disabled else coroutine_when_disabled(hookq)

            # Then we can start this coroutine and ensure it gives us the start signal.
            ok, result = True, next(coro)
            if not isinstance(result, Signal):
                logging.critical(u"{:s}.closure_start({!r}) : Coroutine #{:d} for the {:s}target {:s} returned a non-signal ({!r}) which will be explicitly returned.".format('.'.join([__name__, self.__class__.__name__]), target, len(State.running_queue), 'disabled ' if target in self.__disabled else '', self.__formatter__(target), result))
                ok = False

            elif result != State.BEGIN:
                logging.critical(u"{:s}.closure_start({!r}) : Coroutine #{:d} for the {:s}target {:s} was unable to be started due to an unexpected signal ({!r}).".format('.'.join([__name__, self.__class__.__name__]), target, len(State.running_queue), 'disabled ' if target in self.__disabled else '', self.__formatter__(target), result))
                ok = False

            # If starting that coroutine actually failed, then we need to
            # bail here without adding it to the current running queue.
            if not ok:
                logging.warning(u"{:s}.closure_start({!r}) : Coroutine #{:d} for the {:s}target {:s} was not created due to a prior critical error.".format('.'.join([__name__, self.__class__.__name__]), target, len(State.running_queue), 'disabled ' if target in self.__disabled else '', self.__formatter__(target)))
                return None if isinstance(result, Signal) else result

            # We should be good and can safely append our started coroutine to the running queue.
            State.running_queue.append(coro)

            # Our coroutine has been properly started, so we can just act as-if the
            # coroutine is being resumed and hand-off execution to the "resume" closure.
            logging.debug(u"{:s}.closure_start({!r}) : Coroutine #{:d} for the {:s}target {:s} was started and will process its priority queue of {:d} item{:s}.".format('.'.join([__name__, self.__class__.__name__]), target, len(State.running_queue), 'disabled ' if target in self.__disabled else '', self.__formatter__(target), len(hookq), '' if len(hookq) == 1 else 's'))
            return closure_resume(*args, **kwargs)

        # This closure is responsible for interrupting execution of the coroutine. Essentially it
        # safely executes the coroutine before closing it, and then popping it from the running queue.
        def closure_cancel(*args, **kwargs):
            '''This closure is responsible for forcefully closing an already started, but currently suspended coroutine.'''
            parameters = args, kwargs
            parameters_description = format_parameters(*args, **kwargs)

            # Grab the current running queue and check if it's empty. If it is, then we were
            # called in error with nothing to cancel. So, we complain about it and then bail.
            if not State.running_queue:
                logging.warning(u"{:s}.closure_cancel({!r}) : Unable to cancel the coroutine for the {:s}target {:s} due to its running queue being empty.".format('.'.join([__name__, self.__class__.__name__]), target, 'disabled ' if target in self.__disabled else '', self.__formatter__(target)))
                return State.END

            # Grab whatever coroutine we're supposed to cancel from the run queue. If the latest coroutine has
            # been started, then we're good to go. If the coroutine is currently running, though, then don't
            # do shit. This is because we've actually been called in error, and the caller should've checked.
            coro = State.running_queue[-1]

            if coro is not None and any([not is_coroutine_started(coro), is_coroutine_running(coro)]):
                logging.debug(u"{:s}.closure_cancel({!r}) : Coroutine #{:d} for the {:s}target {:s} with parameters ({:s}) {:s} and will have its signal ignored.".format('.'.join([__name__, cls.__name__]), target, len(State.running_queue), 'disabled ' if target in self.__disabled else '', self.__formatter__(target), parameters_description, 'is currently running' if is_coroutine_running(coro) else 'has not been started'))

            elif coro is None:
                logging.debug(u"{:s}.closure_cancel({!r}) : Coroutine #{:d} for the {:s}target {:s} with parameters ({:s}) is missing from the running queue and will have its signal ignored.".format('.'.join([__name__, cls.__name__]), target, len(State.running_queue), 'disabled ' if target in self.__disabled else '', self.__formatter__(target), parameters_description))

            else:
                logging.debug(u"{:s}.closure_cancel({!r}) : Coroutine #{:d} for the {:s}target {:s} will be sent the parameters ({:s}) to retrieve its signal.".format('.'.join([__name__, cls.__name__]), target, len(State.running_queue), 'disabled ' if target in self.__disabled else '', self.__formatter__(target), parameters_description))

            result = coro.send(parameters) if coro is not None and all([is_coroutine_started(coro), not is_coroutine_running(coro)]) else State.END

            # If the result we got back from the already-existing coroutine is not
            # State.END, then our last execution did not complete for some reason.
            if result != State.END:
                logging.debug(u"{:s}.closure_cancel({!r}) : Coroutine #{:d} for the {:s}target {:s} returned an unexpected signal ({!r}) and will require consuming {:d} item{:s} from its queue.".format('.'.join([__name__, self.__class__.__name__]), target, len(State.running_queue), 'disabled ' if target in self.__disabled else '', self.__formatter__(target), result, len(self.__cache.get(target, [])), '' if self.__cache.get(target, []) == 1 else 's'))

                logging.debug(u"{:s}.closure_cancel({!r}) : Coroutine #{:d} for the {:s}target {:s} has discarded the first {:s} due to being canceled.".format('.'.join([__name__, self.__class__.__name__]), target, len(State.running_queue), 'disabled ' if target in self.__disabled else '', self.__formatter__(target), "ignored result ({!r})".format(result) if isinstance(result, (Signal, internal.types.none)) else "result ({!r})".format(result)))
                while result != State.END:
                    result = coro.send(parameters)
                    logging.debug(u"{:s}.closure_cancel({!r}) : Coroutine #{:d} for the {:s}target {:s} has discarded the next {:s} due to being canceled.".format('.'.join([__name__, self.__class__.__name__]), target, len(State.running_queue), 'disabled ' if target in self.__disabled else '', self.__formatter__(target), "ignored result ({!r})".format(result) if isinstance(result, (Signal, internal.types.none)) else "result ({!r})".format(result)))

                assert(result == State.END)

            else:
                logging.debug(u"{:s}.closure_cancel({!r}) : Coroutine #{:d} for the {:s}target {:s} has received a signal ({!r}) with the parameters ({:s}).".format('.'.join([__name__, cls.__name__]), target, len(State.running_queue), 'disabled ' if target in self.__disabled else '', self.__formatter__(target), result, parameters_description))

            # If the coroutine is not running, then we can close this
            # thing, remove it from our running queue, and move on.
            if not is_coroutine_running(coro):
                coro.close()

            if is_coroutine_stopped(coro):
                State.running_queue.pop()
            return result

        # This closure is responsible for stopping the coroutine, and is intended to be
        # the last thing that gets called when the coroutine returns its END state.
        def closure_stop(*args, **kwargs):
            '''This closure is responsible for finishing execution of the coroutine and should be called to complete execution of the coroutine.'''
            parameters = args, kwargs
            parameters_description = format_parameters(*args, **kwargs)

            # If the coroutine is not actually in our running queue, then there's nothing to do.
            if not State.running_queue:
                logging.debug(u"{:s}.closure_stop({!r}) : Unable to stop the coroutine for the {:s}target {:s} due to its running queue being empty and already stopped.".format('.'.join([__name__, self.__class__.__name__]), target, 'disabled ' if target in self.__disabled else '', self.__formatter__(target)))
                return

            # First we'll grab the last coroutine from our current running queue. This is specifically
            # to deal with recursion, where the callable for a handler results in another handler
            # being dispatched. We'll give it our parameters in order to check if it really completed.
            coro = State.running_queue[-1]
            logging.debug(u"{:s}.closure_stop({!r}) : Coroutine #{:d} for the {:s}target {:s} will be sent the parameters ({:s}) to retrieve its signal.".format('.'.join([__name__, cls.__name__]), target, len(State.running_queue), 'disabled ' if target in self.__disabled else '', self.__formatter__(target), parameters_description))
            result = coro.send(parameters)

            # If the result we got back from the coroutine is not State.END, then we're apparently not
            # really done. Still, our job is to close it out and so we proceed to empty the coroutine.
            if result != State.END:
                logging.debug(u"{:s}.closure_stop({!r}) : Coroutine #{:d} for the {:s}target {:s} returned an unexpected signal ({!r}) and will require consuming {:d} item{:s} from its queue.".format('.'.join([__name__, self.__class__.__name__]), target, len(State.running_queue), 'disabled ' if target in self.__disabled else '', self.__formatter__(target), result, len(self.__cache.get(target, [])), '' if self.__cache.get(target, []) == 1 else 's'))

                logging.debug(u"{:s}.closure_stop({!r}) : Coroutine #{:d} for the {:s}target {:s} has discarded the first {:s} due to requested stop.".format('.'.join([__name__, self.__class__.__name__]), target, len(State.running_queue), 'disabled ' if target in self.__disabled else '', self.__formatter__(target), "ignored result ({!r})".format(result) if isinstance(result, (Signal, internal.types.none)) else "result ({!r})".format(result)))
                while result != State.END:
                    result = coro.send(parameters)
                    logging.debug(u"{:s}.closure_stop({!r}) : Coroutine #{:d} for the {:s}target {:s} has discarded the next {:s} due to requested stop.".format('.'.join([__name__, self.__class__.__name__]), target, len(State.running_queue), 'disabled ' if target in self.__disabled else '', self.__formatter__(target), "ignored result ({!r})".format(result) if isinstance(result, (Signal, internal.types.none)) else "result ({!r})".format(result)))

                assert(result == State.END)

            else:
                logging.debug(u"{:s}.closure_stop({!r}) : Coroutine #{:d} for the {:s}target {:s} has received a signal ({!r}) with parameters ({:s}).".format('.'.join([__name__, cls.__name__]), target, len(State.running_queue), 'disabled ' if target in self.__disabled else '', self.__formatter__(target), result, parameters_description))

            # We should now be safe to close it since we received the correct signal.
            logging.debug(u"{:s}.closure_stop({!r}) : Coroutine #{:d} for the {:s}target {:s} will be closed after receiving result ({!r}).".format('.'.join([__name__, cls.__name__]), target, len(State.running_queue), 'disabled ' if target in self.__disabled else '', self.__formatter__(target), result))
            coro.close()

            # If the coroutine has been properly stopped, then we can remove it from the
            # running queue. If for some reason it didn't stop, which should NEVER happen,
            # then we avoid removing it here and expect some else to later remove it.
            if is_coroutine_stopped(coro):
                State.running_queue.pop()
            return

        # This closure is responsible for resuming execution of the currently running
        # coroutine. It continues to execute callables until one of them returns something.
        def closure_resume(*args, **kwargs):
            '''This closure is responsible for resuming execution of the coroutine and should be attached in order to allow better hooking.'''
            parameters = args, kwargs
            parameters_description = format_parameters(*args, **kwargs)

            # First check to see if our running queue has something inside it. If it doesn't, then we
            # can hand off execution to closure_start which should initialize it and then call us back.
            if not State.running_queue:
                logging.info(u"{:s}.closure_resume({!r}) : Ignoring the {:s}target {:s} due to the running queue being empty.".format('.'.join([__name__, self.__class__.__name__]), target, 'disabled ' if target in self.__disabled else '', self.__formatter__(target)))
                return

            # Then we can grab our very latest coroutine and confirm that it was actually started.
            coro = State.running_queue[-1]
            if not is_coroutine_started(coro):
                logging.critical(u"{:s}.closure_resume({!r}) : Coroutine #{:d} for the {:s}target {:s} was unable to be resumed due to it not having been started.".format('.'.join([__name__, self.__class__.__name__]), target, len(State.running_queue), 'disabled ' if target in self.__disabled else '', self.__formatter__(target)))
                return

            # Before we do anything, though, we need to verify that the target has not
            # been explicitly disabled. If it has been, then we can just return nothing.
            if target not in self.__cache or target in self.__disabled:
                return

            # Now, we're safe to continuously feed it things until it actually gives up a result.
            logging.debug(u"{:s}.closure_resume({!r}) : Sending parameters ({:s}) to coroutine #{:d} for the {:s}target {:s}.".format('.'.join([__name__, cls.__name__]), target, parameters_description, len(State.running_queue), 'disabled ' if target in self.__disabled else '', self.__formatter__(target)))
            result = coro.send(parameters)

            while isinstance(result, internal.types.none):
                logging.debug(u"{:s}.closure_resume({!r}) : Sending parameters ({:s}) to coroutine #{:d} for the {:s}target {:s}.".format('.'.join([__name__, cls.__name__]), target, parameters_description, len(State.running_queue), 'disabled ' if target in self.__disabled else '', self.__formatter__(target)))
                result = coro.send(parameters)

            # If our result is an instance of a Signal type, then we're done executing.
            if isinstance(result, (Signal, internal.types.none)):
                logging.debug(u"{:s}.closure_resume({!r}) : Coroutine #{:d} for the {:s}target {:s} finished without a result ({!r}) to return to the caller.".format('.'.join([__name__, cls.__name__]), target, len(State.running_queue), 'disabled ' if target in self.__disabled else '', self.__formatter__(target), result))
                return

            # Otherwise this is an actual result that we captured from an
            # executed callable, and we need to return it to the caller.
            logging.debug(u"{:s}.closure_resume({!r}) : Coroutine #{:d} for the {:s}target {:s} finished with a captured result ({!s}) to return to the caller.".format('.'.join([__name__, cls.__name__]), target, len(State.running_queue), 'disabled ' if target in self.__disabled else '', self.__formatter__(target), result))
            return result

        # That's it. We just need to cache the closures that capture our current scope and
        # process the callables assigned to the specified target, and then we can return them.
        self.__target_scopes[target] = State
        result = closure_start, closure_resume, closure_stop
        State.references = [weakref.ref(item) for item in result]
        return count, tuple(ref() for ref in State.references)

    def detach(self, target):
        """Detach the given `target` and return whether or not the target was removed successfully.

        This method is intended to be called as a supermethod for the specified `target`.
        """
        cls = self.__class__

        # First count the number of references that we're going to return later.
        mutex, queue_ = self.__cache.get(target, (threading.Lock(), []))
        with mutex:
            count = len(queue_)

        # If the target hasn't been attached, then there's really nothing to do.
        if target not in self.__target_scopes:
            logging.warning(u"{:s}.detach({!r}) : Unable to detach from target {:s} due to it not being attached.".format('.'.join([__name__, self.__class__.__name__]), target, self.__formatter__(target)))
            return False

        # Grab each component that composes the scope for the selected target,
        # and check their references. If they're all none, then we can pop them
        # from our scopes and return success. Otherwise they're still in use.
        state = self.__target_scopes.pop(target)
        if all(ref() is None for ref in state.references):
            return True

        # Otherwise we'll log a debug message describing how many references are left.
        references = [0 if ref() is None else sys.getrefcount(ref()) - 1 for ref in state.references]
        logging.debug(u"{:s}.detach({!r}) : Target {:s} is still being referenced by {:d} object{:s} ({:s}).".format('.'.join([__name__, cls.__name__]), target, self.__formatter__(target), sum(references), '' if sum(references) == 1 else 's', ', '.join(map("{:d}".format, references))))
        return True

class priorityhook(prioritybase):
    """
    Helper class for allowing one to apply a number of hooks to the
    different hook points within IDA.
    """
    def __init__(self, klass, mapping={}, entries={}):
        '''Construct an instance of a priority hook with the specified IDA hook type which can be one of ``idaapi.*_Hooks``.'''
        super(priorityhook, self).__init__()

        # stash away our hook class that we will use for attaching our hook
        # and create a dictionary that contains the callables we need to attach.
        self.__klass__ = klass
        self.__attached__ = {}

        # we also maintain 2 other dictionaries that contain instances of the hook object
        # that executes a hook's priority queue, and the other for the queue's scope.
        self.__attached_instances = {}
        self.__attached_scope = {}

        # enumerate all of the attachable methods and store them in easily accessible set.
        self.__attachable__ = { name for name in klass.__dict__ if not name.startswith('__') and name not in {'hook', 'unhook', 'thisown'} }

        # stash away our mapping of supermethods so that we can return the
        # right one when we're asked to generate them for __supermethod__.
        self.__mapping__ = mapping

        # stash away our mapping for entrymethods so that we can use it to
        # generate our closure to convince IDAPython's SWIG that we're using the
        # correct number of arguments for a hook point.
        self.__entries__ = entries

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

    def __format__(self, spec):
        return internal.utils.pycompat.fullname(self.__klass__)

    def __formatter__(self, name):
        cls = self.__klass__
        if isinstance(name, internal.types.string):
            return '.'.join([cls.__name__, name])
        elif isinstance(name, internal.types.integer):
            return "{:#x}".format(name)
        return "{!s}".format(name)

    def __new_instance__(self, attributes):
        '''Create a new instance of the hook object with the callables in `attributes` attached as methods.'''
        klass = self.__klass__

        # First we need to iterate through all of the attributes in order to
        # gather the items that we'll use to generate a closure.
        methods = {}
        for name, callable in attributes.items():
            locals = {}

            # Assign some parameters that we need to feed into our closure.
            locals['target'], locals['callable'] = name, callable
            locals['supermethod'] = self.__supermethod__(name)
            locals['entrypoint'] = self.__entries__.get(name)

            # Generate a closure that will later be converted into a method. The
            # function (method) being returned is responsible for dispatching to
            # a callable and then checking its result. If a non-`None` result
            # was returned, then we can just return it. Otherwise, we chain into
            # the supermethod for the hook so that we don't interfere with
            # anything that the disassembler wants to do.
            def closure(locals):
                """
                Returns a function that will be attached as a method to the hook
                object associated with this class. The job of the returned
                function is to dispatch to the user function that is stored in
                `locals` as "callable".

                After dispatching to the callable, we check if a result was
                returned, and return it if so. Otherwise, we dispatch to the
                supermethod that is in `locals` under "supermethod".
                """
                def method(instance, *args, **kwargs):
                    target, callable, supermethod = (locals[item] for item in ['target', 'callable', 'supermethod'])
                    result = callable(*args, **kwargs)

                    # If we didn't get a result to return, then just dispatch
                    # to the supermethod so that we don't interfere with anything.
                    if result is None:
                        return supermethod(instance, *args, **kwargs)

                    # Otherwise we return the code that was given to us.
                    logging.debug(u"{:s}.method({:s}) : Received a value ({!r}) to return from the callable ({:s}) for target {:s}.".format('.'.join([__name__, self.__class__.__name__]), self.__formatter__(target), result, internal.utils.pycompat.fullname(callable), self.__formatter__(target)))
                    return result

                # The first parameter in the following function (that we ignore)
                # basically contains the template function that we are wrapping
                # with the `utils.wrap` decorator. The function that is returned
                # by the decorator will call our "entrymethodwrapper" function
                # with the template as its first parameter, followed by rest of
                # the arguments from the template function.
                def entrymethodwrapper(_, instance, *args, **kwargs):
                    """
                    This function is basically a dispatcher that will dispatch
                    to the "method" function above us. It is intended to be
                    called by the entrypoint that we attach in "target".
                    """
                    return method(instance, *args, **kwargs)

                # If a custom entrypoint was specified, then we return a wrapper
                # with the same definitionkas the entrypoint which will call the
                # "method" function in response to the hook being dispatched.
                if locals['entrypoint']:
                    return internal.utils.wrap(locals['entrypoint'], entrymethodwrapper)
                return method

            # We've generated the closure to use and so we can store it in
            # our dictionary that will be converted into methods.
            methods[name] = closure(locals)

        # Now we can use the methods we generated and stored in our dictionary to
        # create a new type and use it to instantiate a new hook object.
        klass_t = type(klass.__name__, (klass,), {attribute : callable for attribute, callable in methods.items()})
        return klass_t()

    @property
    def available(self):
        '''Return all of the hook targets that can be attached to.'''
        return {name for name in self.__attachable__}

    def list(self, *pattern):
        """List all of the available hook targets with their prototype and description.

        If a glob is passed as a `pattern`, the only the events matching the
        specified pattern will be listed.
        """
        klass, targets = self.__klass__, sorted(self.available)
        attributes = {item : getattr(klass, item) for item in targets}
        documentation = {item : autodocumentation.__doc__ for item, autodocumentation in attributes.items()}

        # If there weren't any attributes, then we can just leave.
        if not targets:
            return six.print_(u"There are no available targets for {:s}.".format(klass.__name__))

        # Define a closure that we can use to extract the parameters from the documentation.
        # FIXME: This should be extracting the actual documentation instead of just the prototype.
        def parameters(doc):
            filtered = filter(None, doc.split('\n'))
            prototype = next(item for item in filtered)
            replaced = prototype.replace('self, ', '').replace('(self)', '()')
            return replaced.strip()

        # Figure out the lengths of each of the columns so that we can align them.
        length = max(map(len, map("{:s}:".format, targets)))

        # Figure out what to match for if we were given a pattern.
        Fmatch = re.compile(fnmatch.translate(*pattern), re.IGNORECASE).match if pattern else internal.utils.fconstant(True)

        # Iterate through all of the sorted items and output them.
        six.print_(u"List of events for {:s}".format(klass.__name__))
        for item in targets:
            doc = documentation[item]
            if Fmatch(item):
                six.print_(u"{:<{:d}s} {:s}".format("{:s}:".format(item), length, parameters(doc)))
            continue
        return

    def close(self):
        '''Detach from all of the hook targets that are currently attached and disconnect the instance.'''
        cls = self.__class__
        ok = super(priorityhook, self).close()
        if not ok:
            targets, count = len(self.__attached__), sum(itertools.chain.from_iterable([2 if name in self.__attached_scope else 0, len(self.__attached_instances.get(name, []))] for name in self.__attached__))
            logging.critical(u"{:s}.close() : Error trying to detach from {:d} attached target{:s} distributed between {:d} instance{:s}.".format('.'.join([__name__, cls.__name__]), targets, '' if targets == 1 else 's', count, '' if count == 1 else 's'))

        # Log every instance that we were not able to detach.
        if not ok:
            for name in sorted(self.__attached__):
                if name in self.__attached_scope:
                    start, stop = self.__attached_scope[name]
                    logging.debug(u"{:s}.close() : Detaching target {:s} still resulted in both management instances ({!s} and {!s}) being hooked to the target {:s}.".format('.'.join([__name__, cls.__name__]), self.__formatter__(target), start, stop, self.__formatter__(target)))

                elif self.__attached_instances.get(name, []):
                    count = len(self.__attached_instances.get(name, []))
                    logging.debug(u"{:s}.close() : Detaching target {:s} left {:d} instance{:s} still being hook to the target {:s}.".format('.'.join([__name__, cls.__name__]), self.__formatter__(target), count, '' if count == 1 else 's', self.__formatter__(target)))

                continue

            names = [name for name in sorted(self.__attached__) if any([name in self.__attached_scope, name in self.__attached_instances])]
            iterable = itertools.chain(map(self.__formatter__, names[:-1]), ("and {:s}".format(self.__formatter__(name)) for name in names[-1:])) if len(names) > 2 else [' and '.join(map(self.__formatter__, names))]
            logging.info(u"{:s}.close() : Hooks for target{:s} {:s} were not able to be completely closed.".format('.'.join([__name__, cls.__name__]), '' if len(names) == 1 else 's', ', '.join(iterable)))

        # That was all we needed to do. If there's still some shit left in any of our attached
        # dictionaries, we need to log a warning since we couldn't disconnect some of them.
        elif any([self.__attached__, self.__attached_scope, self.__attached_instances]):
            used = sorted({name for name in itertools.chain(self.__attached__, self.__attached_scope, self.__attached_instances)})
            iterable = itertools.chain(used[:-1], map("and {:s}".format, used[-1:])) if len(used) > 2 else used
            description = ', '.join(iterable) if len(used) > 2 else ' and '.join(iterable)
            logging.critical(u"{:s}.close() : Error trying to close the hook object due to {:d} target{:s} ({:s}) still being connected.".format('.'.join([__name__, cls.__name__]), len(used), '' if len(used) == 1 else 's', description))
        return False if self.__attached__ else True

    def __attach_managers(self, name):
        '''Create and attach the necessary objects for managing the hook specified by `name`.'''
        assert(all(name not in attached for attached in [self.__attached__, self.__attached_scope, self.__attached_instances]))

        # First we'll call our supermethod to get the callables that manage the scope.
        count, packed = super(priorityhook, self).attach(name)

        # Then we'll unpack our callables, and instantiate the two required objects.
        start_attributes, resume_attributes, stop_attributes = ({name : callable} for callable in packed)
        start_instance, stop_instance = (self.__new_instance__(attributes) for attributes in [start_attributes, stop_attributes])

        # Now we'll try to start them. The disassembler's hooks appear to be
        # stored in a stack, so we need to enable them in reverse order.
        cls = self.__class__
        if not stop_instance.hook():
            logging.debug(u"{:s}._attach_managers({!r}) : Unable to hook the management instance ({!s}) for the target {:s} which will result in the target remaining detached.".format('.'.join([__name__, cls.__name__]), name, stop_instance, self.__formatter__(name)))
            return False

        # If we failed at enabling the starting hook, then we need to
        # remove the hook that did succeed and then return failure.
        if not start_instance.hook():
            logging.debug(u"{:s}._attach_managers({!r}) : Unable to hook the management instance ({!s}) for the target {:s} which will result in the target remaining detached.".format('.'.join([__name__, cls.__name__]), name, start_instance, self.__formatter__(name)))

            if not stop_instance.unhook():
                logging.warning(u"{:s}._attach_managers({!r}) : Another error occurred while trying to detach the management instance ({!s}) from the target {:s}.".format('.'.join([__name__, cls.__name__]), name, stop_instance, self.__formatter__(name)))

            return False

        # Now we can assign our instances that manage the scope for our
        # hook, and stash our callables within our "attached" dictionary.
        self.__attached__[name] = packed
        self.__attached_scope[name] = start_instance, stop_instance
        self.__attached_instances[name] = []

        return True

    def __attach_update(self, name):
        '''Update the number of hooks that are attached to the hook specified by `name`.'''
        assert(all(name in attached for attached in [self.__attached__, self.__attached_scope, self.__attached_instances]))

        # First we'll call our supermethod to get the number of hooks for
        # the target that will need to be attached for things to work.
        count, packed = super(priorityhook, self).attach(name)
        assert(all(attached == required for attached, required in zip(self.__attached__[name], packed)))

        # Now we can unpack all of the packed callables. We stash them into a
        # diciontary that we can use directly as the attributes for a new instance.
        start_attributes, resume_attributes, stop_attributes = ({name : callable} for callable in self.__attached__[name])

        # If the current number of instances is smaller than
        # our count, then we create instances until they match.
        cls, current, hook, unhook = self.__class__, len(self.__attached_instances[name]), [], []
        if current < count:
            while current + len(hook) < count:
                instance = self.__new_instance__(resume_attributes)
                hook.append(instance)
            logging.debug(u"{:s}.__attach_update({!r}) : Created {:d} instance{:s} for the hook target {:s} which requires {:d} instance{:s}.".format('.'.join([__name__, cls.__name__]), name, len(hook), '' if len(hook) else 's', self.__formatter__(name), count, '' if count == 1 else 's'))

        # If we have too many instances, then we remove until they match.
        elif current > count:
            while current - len(unhook) > count:
                instance = self.__attached_instances[name].pop()
                unhook.append(instance)
            logging.debug(u"{:s}.__attach_update({!r}) : Removed {:d} instance{:s} from the hook target {:s} which requires {:d} instancce{:s}.".format('.'.join([__name__, cls.__name__]), name, len(unhook), '' if len(unhook) == 1 else 's', self.__formatter__(name), count, '' if count == 1 else 's'))

        # Now we'll need to try and disable everything because we'll
        # need to re-enable all the hooks in the correct order.
        remaining, instances = [], [instance for instance in itertools.chain(self.__attached_instances[name], unhook)]
        for index, instance in enumerate(instances):
            if not instance.unhook():
                remaining.append(index)
            continue

        if remaining:
            logging.warning(u"{:s}.__attach_update({!r}) : Error trying to unhook {:d} out of {:d} instance{:s} from the hook target {:s}.".format('.'.join([__name__, cls.__name__]), name, len(remaining), len(instances), '' if len(instances) == 1 else 's', self.__formatter__(name)))

        # Then we can try and disable the management hooks. If we fail
        # at anything, then we actually failed the whole attachment.
        errors, managers = [], self.__attached_scope[name]
        for index, instance in enumerate(managers):
            if instance is not None and not instance.unhook():
                errors.append(instance)
            continue

        if errors:
            logging.warning(u"{:s}.__attach_update({!r}) : Error trying to unhook {:d} out of {:d} management instance{:s} for the hook target {:s}.".format('.'.join([__name__, cls.__name__]), name, len(errors), len(scope), '' if len(scope) == 1 else 's', self.__formatter__(name)))

        # If anything failed, then we can just put everything that we couldn't
        # hook back into our dictionaries, and then we can bail with a failure.
        if remaining or errors:
            self.__attached_instances[name][:] = [instances[index] for index in remaining]
            self.__attached_scope[name] = tuple(instance if any(error == instance for error in errors) else None for instance in managers)
            return False

        # Otherwise we were succesful, and we can empty out all of our
        # dictionaries so that it appears as if the target is unattached.
        packed = self.__attached__.pop(name)
        managers = start_instance, stop_instance = self.__attached_scope.pop(name)
        available = self.__attached_instances.pop(name)

        # Then we can start over and attach each instance in their reversed order.
        if not stop_instance.hook():
            logging.warning(u"{:s}.__attach_update({!r}) : Unable to hook the management instance ({!s}) for the hook target {:s} which will result in the target {:s} being detached.".format('.'.join([__name__, cls.__name__]), name, stop_instance, self.__formatter__(name), self.__formatter__(name)))
            return False

        # Then we'll try and hook all the instances that we have.
        unavailable, instances = [], [instance for instance in itertools.chain(available, hook)]
        for index, instance in enumerate(instances):
            if not instance.hook():
                unavailable.append(index)
            continue

        if unavailable:
            logging.warning(u"{:s}.__attach_update({!r}) : Error trying to hook {:d} out of {:d} instance{:s} for hook target {:s} which will result in the target {:s} being unreliable.".format('.'.join([__name__, cls.__name__]), name, len(unavailable), len(instances), '' if len(instances) == 1 else 's', self.__formatter__(name), self.__formatter__(name)))

        # For last, we can try to enable the starting hook. If this ends up failing
        # for some strange reason, then we need to update our dictionaries and bail.
        ok = start_instance.hook()
        if not ok:
            logging.warning(u"{:s}.__attach_update({!r}) : Unable to hook the management instance ({!s}) for the hook target {:s} which will result in the target {:s} being detached.".format('.'.join([__name__, cls.__name__]), name, start_instance, self.__formatter__(name), self.__formatter__(name)))

        if unavailable or not ok:
            failed = {index for index in unavailable}
            self.__attached_instances[name][:] = [instance for index, instance in enumerate(instances) if index not in failed]
            self.__attached_scope[name] = (start_instance, stop_instance) if ok else (None, stop_instance)
            self.__attached__[name] = packed
            return False

        # Otherwise everything was successful and we can update our dictionaries.
        self.__attached_instances[name] = instances
        self.__attached_scope[name] = managers
        self.__attached__[name] = packed
        return True

    def attach(self, name):
        '''Attach the target specified by `name` to the hook object.'''
        cls = self.__class__
        if name not in self.__attachable__:
            raise NameError(u"{:s}.attach({!r}) : Unable to attach to the target {:s} due to the target being unavailable.".format('.'.join([__name__, cls.__name__]), name, self.__formatter__(name)))

        # First we'll call our supermethod to figure out how many references
        # that we'll need to create in order to properly attach to the target.
        count, packed = super(priorityhook, self).attach(name)

        # If the target has not yet been attached, we'll need to create
        # instances of the hook objects for managing the target's scope.
        ok = True if name in self.__attached__ else self.__attach_managers(name)

        # Now we can give the target an update and hope that it succeeds.
        if ok:
            assert(all(name in attached for attached in [self.__attached__, self.__attached_scope, self.__attached_instances]))
            return self.__attach_update(name)

        # Otherwise we failed miserably and so we can just bail here.
        logging.warning(u"{:s}.attach({!r}) : Unable to attach {:d} hook instance{:s} ({:s}) to the specified target {:s}.".format('.'.join([__name__, cls.__name__]), name, count, '' if count == 1 else 's', internal.utils.pycompat.fullname(self.__klass__), self.__formatter__(name)))
        return False

    def __detach_unhook(self, name):
        '''Iterate through the known instances for the target `name` and remove their hooks in the correct order.'''
        assert(all(name in attached for attached in [self.__attached__, self.__attached_scope, self.__attached_instances]))

        # Iterate through all known instances for the target and unhook them.
        cls, failed, instances = self.__class__, [], self.__attached_instances[name]
        for index, instance in enumerate(instances):
            if not instance.unhook():
                logging.warning(u"{:s}.__detach_unhook({!r}) : Unable to unhook instance ({!s}) {:d} of {:d} for the hook target {:s}.".format('.'.join([__name__, cls.__name__]), name, instance, 1 + index, len(instances), self.__formatter__(name)))
                failed.append(index)
            continue

        # If we couldn't unhook them, then log a warning to let the user know.
        if failed:
            iterable = itertools.chain(map("{:d}".format, failures[:-1]), map("and {:d}".format, failures[-1:])) if len(failures) > 2 else map("{:d}".format, failures)
            description = ' and '.join(iterable) if len(failures) == 2 else ', '.join(iterable)
            logging.critical(u"{:s}.__detach_unhook({!r}) : Unable to unhook {:d} instance{:s} ({:s}) that {:s} hooking the target {:s}.".format('.'.join([__name__, cls.__name__]), name, len(failures), '' if len(failures) == 1 else 's', description, 'is' if len(failures) == 1 else 'are', self.__formatter__(name)))

        # Update our dictionary of instances that are currently still attached.
        remaining = {index for index in failed}
        self.__attached_instances[name][:] = [instance for index, instance in enumerate(instances) if index in remaining]

        # Now we can go through and unhook the instances that manage the scope.
        managers = start_instance, stop_instance = self.__attached_scope[name]

        start_removed = start_instance.unhook()
        if not start_removed:
            logging.warning(u"{:s}.__detach_unhook({!r}) : Unable to unhook the management instance ({!s}) for the hook target {:s}.".format('.'.join([__name__, cls.__name__]), name, start_instance, self.__formatter__(name)))

        stop_removed = stop_instance.unhook()
        if not stop_removed:
            logging.warning(u"{:s}.__detach_unhook({!r}) : Unable to unhook the management instance ({!s}) for the hook target {:s}.".format('.'.join([__name__, cls.__name__]), name, stop_instance, self.__formatter__(name)))

        # If we couldn't do either, then technically our hooks are still attached. However,
        # since the intermediary hooks have been removed, the hooks aren't guaranteed execution.
        if all([not start_removed, not stop_removed]):
            logging.critical(u"{:s}.__detach_unhook({!r}) : Unable to unhook the management instances ({:s} and {:s}) for the hook target {:s} which will result in hooks being unreliable.".format('.'.join([__name__, cls.__name__]), name, start_instance, stop_instance, self.__formatter__(name)))

        elif any([not stop_removed, not start_removed]):
            description = "management instance ({!s})".format(stop_instance) if not stop_removed else "management instance ({!s})".format(start_instance) if not start_removed else "management instances ({!s} and {!s})".format(start_instance, stop_instance)
            logging.warning(u"{:s}.__detach_unhook({!r}) : Unable to unhook the {:s} from target {:s} which will result in the appearance of the target being disabled.".format('.'.join([__name__, cls.__name__]), name, description, self.__formatter__(name)))

        # Now we can update our dictionary and return whether we succeeded or not.
        iterable = (None if removed else instance for instance, removed in zip(managers, [start_removed, stop_removed]))
        self.__attached_scope[name] = managers = tuple(iterable)
        return False if remaining or any(managers) else True

    def detach(self, name):
        '''Detach the target specified by `name` from the hook object.'''
        cls = self.__class__
        if name not in self.__attachable__:
            raise NameError(u"{:s}.detach({!r}) : Unable to detach from the target {:s} due to the target being unavailable.".format('.'.join([__name__, cls.__name__]), name, self.__formatter__(name)))

        # Check that the target name is currently attached.
        elif name not in self.__attached__:
            logging.warning(u"{:s}.detach({!r}) : Unable to detach from the target {:s} as it is not currently attached.".format('.'.join([__name__, cls.__name__]), name, self.__formatter__(name)))
            return False

        assert(name in self.__attached_scope)
        assert(name in self.__attached_instances)

        # First we'll unhook everything. This is required so that we free up references.
        if not self.__detach_unhook(name):
            logging.warning(u"{:s}.detach({!r}) : Unable to detach from the target {:s} due to being unable to completely unhook {:d} attached instance{:s}.".format('.'.join([__name__, cls.__name__]), name, self.__formatter__(name), len(self.__attached_instances[name]), '' if len(self.__attached_instances[name]) == 1 else 's'))
            return False

        # Now that everything was unhooked, we can start emptying out instances.
        instances = self.__attached_instances[name]
        while instances:
            instance = instances.pop()
            del(instance)

        # Next we need to remove the "start" and "stop" instances for the target.
        start_instance, stop_instance = self.__attached_scope.pop(name)
        del(start_instance, stop_instance)

        # With luck, that should be everything. So we can pop the target
        # from our attached_instances and our "attached" dictionary.
        instances = self.__attached_instances.pop(name)
        packed = self.__attached__.pop(name)
        del(instances, packed)

        # Then we can finally call our parent class to complete the detach.
        return super(priorityhook, self).detach(name)

    def add(self, name, callable, priority=0):
        '''Add the `callable` to the queue for the specified `name` with the given `priority`.'''
        cls = self.__class__

        # Try and attach to the target name with a closure.
        if not self.attach(name):
            format = "{:+d}".format if isinstance(priority, internal.types.integer) else "{!r}".format
            raise internal.exceptions.DisassemblerError(u"{:s}.add({!r}, {!s}, {:s}) : Unable to attach to the specified hook target {:s}.".format('.'.join([__name__, cls.__name__]), name, callable, format(priority), self.__formatter__(name)))

        # We should've attached, so all that's left is to add it for
        # tracking using the parent method.
        return super(priorityhook, self).add(name, callable, priority)

    def discard(self, name, callable):
        '''Discard the specified `callable` from hooking the event `name`.'''
        if name not in self.__attachable__:
            cls = self.__class__
            raise NameError(u"{:s}.discard({!r}, {!s}) : Unable to discard the callable ({:s}) from the cache due to the target {:s} being unavailable.".format('.'.join([__name__, cls.__name__]), name, callable, internal.utils.pycompat.fullname(callable), self.__formatter__(name)))
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

        # Keep a dict of the 3 callables that manage the scope for a notification.
        self.__attached__ = {}

        # We also need to keep a list of all the callables that we
        # attach because the notify_when api doesn't allow us to
        # assign the same callable to a notification more than once.
        self.__attached_callables = {}

    def __format__(self, spec):
        return internal.utils.pycompat.fullname(idaapi.notify_when)

    def __formatter__(self, notification):
        name = self.__lookup.get(notification, '')
        return "{:s}({:#x})".format(name, notification) if name else "{:#x}".format(notification) if isinstance(notification, internal.types.integer) else "{!r} (notification needs to be an integer)".format(notification)

    @property
    def available(self):
        '''Return all of the notifications that may be attached to.'''
        result = {notification for notification in self.__lookup}
        return sorted(result)

    def __attach_managers(self, notification):
        '''Attach the necessary callables to manage the specified `notification`.'''
        assert(all(notification not in attached for attached in [self.__attached__, self.__attached_callables]))

        # First we'll use our supermethod to unpack the needed callables.
        count, packed = super(prioritynotification, self).attach(notification)
        start, _, stop = packed

        # Notifications get attached in order, so we use the "start" callable first.
        cls = self.__class__
        if not idaapi.notify_when(notification, start):
            logging.warning(u"{:s}.__attach_managers({!r}) : Unable to attach to the {:s} notification with the management callable ({:s}).".format('.'.join([__name__, cls.__name__]), notification, self.__formatter__(notification), internal.utils.pycompat.fullname(start)))
            return False

        # Then we can try to attach the "stop" callable for the notification. If we were
        # successful, then both were attached and we only need to update our dictionaries.
        ok = idaapi.notify_when(notification, stop)
        if ok:
            self.__attached__[notification] = packed
            self.__attached_callables[notification] = []
            return True

        # Otherwise we need to complain about it and then we can try to remove the
        # start callable we attached. If that fails, we can complain about it too.
        logging.warning(u"{:s}.__attach_managers({!r}) : Unable to attach to the {:s} notification with the management callable ({:s}).".format('.'.join([__name__, cls.__name__]), notification, self.__formatter__(notification), internal.utils.pycompat.fullname(stop)))

        if not idaapi.notify_when(notification | idaapi.nw_remove, start):
            logging.critical(u"{:s}.__attach_managers({!r}) : Unable to recover from error and detach the management callable ({:s}) from the {:s} notification.".format('.'.join([__name__, cls.__name__]), notification, internal.utils.pycompat.fullname(start), self.__formatter__(notification)))

        return False

    def __attach_update(self, notification):
        '''Attach the required number of callables to the specified `notification`.'''
        assert(all(notification in attached for attached in [self.__attached__, self.__attached_callables]))

        # Ask our supermethod for the number of callables that are needed, and
        # cross-check the callabes that we received against whatever was saved.
        count, packed = super(prioritynotification, self).attach(notification)
        assert(all(attached == required for attached, required in zip(self.__attached__[notification], packed)))

        # Now we've guaranteed that the notification has been attached to. So, we
        # only need to add callables to the "resume" callable in order to continue.
        packed = self.__attached__[notification]
        start, resume, stop = packed

        # Start by temporarily removing what should be the last notification.
        cls = self.__class__
        if not idaapi.notify_when(notification | idaapi.NW_REMOVE, stop):
            logging.warning(u"{:s}.__attach_update({!r}) : Refusing to attach {:+d} callable to the {:s} notification due to being unable to temporarily remove the management callable ({:s}).".format('.'.join([__name__, cls.__name__]), notification, 1, self.__formatter__(notification), len(internal.utils.pycompat.fullname(stop))))
            return False

        logging.debug(u"{:s}.__attach_update({!r}) : Temporarily removed the management callable ({:s}) that was attached to the {:s} notification.".format('.'.join([__name__, cls.__name__]), notification, internal.utils.pycompat.fullname(stop), self.__formatter__(notification)))

        # Next we just need to create a copy of "resume" that looks different due to
        # the disassembler not allowing the same callable to be used more than once.
        def notification_wrapper_callable(resume, *args, **kwargs):
            return resume(*args, **kwargs)

        # We need to figure out whether we're supposed to add callables
        # to the "resume" callable or adjust our list by removing them.
        callables, add, remove = self.__attached_callables.pop(notification), [], []
        if len(callables) < count:
            while len(callables) + len(add) < count:
                Fnotification_wrapper_callable = functools.partial(notification_wrapper_callable, resume)
                add.append(Fnotification_wrapper_callable)

            logging.debug(u"{:s}.__attach_update({!r}) : Added {:d} callable{:s} to the {:s} notification to meet the required {:d} callable{:s}.".format('.'.join([__name__, cls.__name__]), notification, len(add), '' if len(add) == 1 else 's', self.__formatter__(notification), count, '' if count == 1 else 's'))

        elif len(callables) > count:
            while len(callables) - len(remove) > count:
                Fnotification_wrapper_callable = callables.pop()
                remove.append(Fnotification_wrapper_callable)

            logging.debug(u"{:s}.__attach_update({!r}) : Removed {:d} callable{:s} from the {:s} notification to meet the required {:d} callable{:s}.".format('.'.join([__name__, cls.__name__]), notification, len(remove), '' if len(remove) == 1 else 's', self.__formatter__(notification), count, '' if count == 1 else 's'))

        assert(len(callables) + len(add) - len(remove) == count)

        # To start, we need to remove all of the callables that were registered.
        unsuccessful, removing = [], [callable for callable in itertools.chain(callables, remove)]
        for index, callable in enumerate(removing):
            if not idaapi.notify_when(notification | idaapi.NW_REMOVE, callable):
                unsuccessful.append(index)
            continue

        # If any of them were unsuccessful, then we'll put them back in the list
        # and attempt to remove the start notification so everything is disabled.
        if unsuccessful:
            self.__attached_callables[notification] = [removing[index] for index in unsuccessful]
            logging.warning(u"{:s}.__attach_update({!r}) : Unable to detach {:d} callable{:s} from the {:s} notification.".format('.'.join([__name__, cls.__name__]), notification, len(unsuccessful), '' if len(unsuccessful) == 1 else 's', self.__formatter__(notification)))

            # We can do this with notifications because they pretty much always succeed.
            if not idaapi.notify_when(notification | idaapi.NW_REMOVE, start):
                logging.critical(u"{:s}.__attach_update({!r}) : Unable to recover from the previous warning and completely detach from the {:s} notification.".format('.'.join([__name__, cls.__name__]), notification, self.__formatter__(notification)))
            return False

        # Once the old ones have been removed, then we can register the new ones.
        # Then we just need to register all of the required callables.
        unavailable, adding = [], [callable for callable in itertools.chain(callables, add)]
        for index, callable in enumerate(adding):
            if not idaapi.notify_when(notification, callable):
                unavailable.append(index)
            continue

        # If any of the callables are unavailable due to our inability to be registered, then
        # log whatever it was that we missed and stash what was successful back in the list.
        if unavailable:
            unregistered = {index for index in unavailable}
            logging.warning(u"{:s}.__attach_update({!r}) : Unable to attach {:d} callable{:s} to the {:s} notification to meet the required {:d} callable{:s}.".format('.'.join([__name__, cls.__name__]), notification, len(unregistered), '' if len(unregistered) == 1 else 's', self.__formatter__(notification), count, '' if count == 1 else 's'))

            self.__attached_callables[notification] = [callable for index, callable in enumerate(adding) if index not in unregistered]

            # Try and remove the starting callable that was previously registered
            # for the notification, so that the notification appears disabled.
            if not idaapi.notify_when(notification | idaapi.NW_REMOVE, start):
                logging.critical(u"{:s}.__attach_update({!r}) : Unable to recover from the previous warning and completely detach from the {:s} notification.".format('.'.join([__name__, cls.__name__]), notification, self.__formatter__(notification)))
            return False

        # If we got to this point, then we were successful and all we need to do is
        # restore the temporarily disabled callable used to start the notification.
        ok = idaapi.notify_when(notification, stop)
        if ok:
            logging.debug(u"{:s}.__attach_update({!r}) : Successfully re-attached the temporarily removed management callable ({:s}) to the {:s} notification.".format('.'.join([__name__, cls.__name__]), notification, internal.utils.pycompat.fullname(stop), self.__formatter__(notification)))

        # If that actually worked out, then we can
        # update our dictionaries and return success.
        if ok:
            self.__attached_callables[notification] = adding
            return True

        # Otherwise we need to painstakingly detach from everything.
        logging.warning(u"{:s}.__attach_update({!r}) : Unable to re-attach the callable ({:s}) that was temporarily removed from the {:s} notification.".format('.'.join([__name__, cls.__name__]), notification, internal.utils.pycompat.fullname(stop), self.__formatter__(notification)))
        if not idaapi.notify_when(notification | idaapi.NW_REMOVE, start):
            logging.critical(u"{:s}.__attach_update({!r}) : Unable to recover from the previous warning and completely detach from the {:s} notification.".format('.'.join([__name__, cls.__name__]), notification, self.__formatter__(notification)))

        remaining, callables = [], [callable for callable in adding]
        for index, callable in enumerate(callables):
            if not idaapi.notify_when(notification | idaapi.NW_REMOVE, callable):
                remaining.append(index)
            continue

        if remaining:
            logging.critical(u"{:s}.__attach_update({!r}) : Unable to recover from the previous warning and detach {:d} of {:d} callable{:s} from the {:s} notification.".format('.'.join([__name__, cls.__name__]), notification, len(remaining), len(callables), self.__formatter__(notification)))

        self.__attached_callables[notification] = [callables[index] for index in remaining]
        return False

    def attach(self, notification):
        '''Attach to the specified `notification` in order to receive events from it.'''
        cls = self.__class__

        if not isinstance(notification, internal.types.integer):
            message = '' if isinstance(event, internal.types.integer) else ' (notification needs to be an integer)'
            raise NameError(u"{:s}.attach({!r}) : Unable to attach to the {:s} notification due to the notification being the wrong type{:s}.".format('.'.join([__name__, cls.__name__]), notification, self.__formatter__(notification), message))

        # First we'll ping our supermethod to get the number of callables
        # and the callables to attach to the specified notification.
        count, packed = super(prioritynotification, self).attach(notification)

        # If we haven't attached to the notification before, then create
        # the callable to the notification in all of our dictionaries.
        ok = True if notification in self.__attached__ else self.__attach_managers(notification)
        if not ok:
            return False

        # Ensure that everything is created and attempt to update the notification.
        assert(all(notification in attached for attached in [self.__attached__, self.__attached_callables]))
        return self.__attach_update(notification)

    def __detach_remove(self, notification):
        '''Remove all of the registered callables for the given `notification`.'''
        assert(all(notification in attached for attached in [self.__attached__, self.__attached_callables]))
        cls, packed = self.__class__, self.__attached__[notification]

        # Start by removing our start and stop notifications
        # so that none of them are able to do anything stupid.
        callable, _, _ = packed
        if not idaapi.notify_when(notification | idaapi.NW_REMOVE, callable):
            logging.warning(u"{:s}.__detach_remove({!r}) : Unable to detach the management callable ({:s}) that was attached to the {:s} notification.".format('.'.join([__name__, cls.__name__]), notification, internal.utils.pycompat.fullname(callable), self.__formatter__(notification)))
            return False

        _, _, callable = packed
        if not idaapi.notify_when(notification | idaapi.NW_REMOVE, callable):
            logging.warning(u"{:s}.__detach_remove({!r}) : Unable to detach the management callable ({:s}) that was attached to the {:s} notification.".format('.'.join([__name__, cls.__name__]), notification, internal.utils.pycompat.fullname(callable), self.__formatter__(notification)))
            return False

        # Now we can proceed to go through all of the callables that are
        # attached to the notification and check whether we succeeded.
        remaining, available = [], self.__attached_callables[notification]
        for index, callable in enumerate(self.__attached_callables[notification]):
            if not idaapi.notify_when(notification | idaapi.NW_REMOVE, callable):
                remaining.append(index)
            continue

        # Update our dictionary with whatever is still remaining.
        registered = {index for index in remaining}
        available[:] = [ callable for index, callable in enumerate(available) if index in registered ]

        # If some are remaining, then we can only log a warning
        # and then return our failure back to the caller.
        if remaining:
            logging.warning(u"{:s}.__detach_remove({!r}) : Unable to detach the {:s} notification due to {:d} callable{:s} still being attached.".format('.'.join([__name__, cls.__name__]), notification, self.__formatter__(notification), len(remaining), '' if len(remaining) == 1 else 's'))
        return False if remaining else True

    def detach(self, notification):
        '''Detach from the specified `notification` so that events from it will not be received.'''
        cls = self.__class__

        # If it's not attached, then we need to freak out at the user.
        if notification not in self.__attached__:
            logging.warning(u"{:s}.detach({!r}) : Unable to detach from the {:s} notification as it is not currently attached.".format('.'.join([__name__, cls.__name__]), notification, self.__formatter__(notification)))
            return False

        # Call our helper method that is responsible for
        # detaching everything from the given notification.
        if not self.__detach_remove(notification):
            return False

        # We should be able to delete all callables and call the supermethod to finish.
        callables = self.__attached_callables.pop(notification)
        assert(not(callables))
        del(callables)

        attached = self.__attached__.pop(notification)
        del(attached)

        return super(prioritynotification, self).detach(notification)

    def add(self, notification, callable, priority=0):
        '''Add the `callable` to the queue with the given `priority` for the specified `notification`.'''

        # Notifications are always attached and enabled.
        ok = self.attach(notification)
        if not ok:
            cls = self.__class__
            raise internal.exceptions.DisassemblerError(u"{:s}.add({:#x}, {!s}, {:+d}) : Unable to attach to the {:s} notification.".format('.'.join([__name__, cls.__name__]), notification, callable, priority, self.__formatter__(notification)))

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
            self.__hexrays_module__ = module = ida_hexrays

        # Stash our events so that we can pretty-print all of them to the user.
        self.__events__ = { getattr(module, name) : name for name in dir(ida_hexrays) if name.startswith(('hxe_', 'lxe_')) }

        # Keep a dict of the 3 callables that manage the scope for an event's
        # callback. We also keep a reference count of the hooks so we know how
        # many times the event has been attached, and how many'll need removal.
        self.__attached__ = {}
        self.__attached_scope = {}
        self.__attached_references = {}

    def __format__(self, spec):
        if not getattr(self, '__hexrays_ready__', False):
            return "install_hexrays_callback<{:s}>".format('unavailable')

        module = self.__hexrays_module__
        res = module.install_hexrays_callback
        return internal.utils.pycompat.fullname(res)

    def __formatter__(self, event):
        name = self.__events__.get(event, '')
        return "{:s}({:#x})".format(name, event) if name else "{:#x}".format(event) if isinstance(event, internal.types.integer) else "{!r}".format(event)

    @property
    def available(self):
        '''Return all of the events that one may want to attach to.'''
        result = {event for event in self.__events__}
        return sorted(result)

    def __attach_managers(self, event):
        '''Create and attach the callbacks that are necessary for managing the specified `event`.'''
        assert(all(event not in attached for attached in [self.__attached__, self.__attached_references]))

        # First we'll need our supermethod to get us the callables to use.
        count, packed = super(priorityhxevent, self).attach(event)

        # Then we'll need to define the following callbacks because we want to
        # hide the event code from the user. Also, the decompiler wants a 0
        # as its result unless the event type explicitly specifies otherwise.
        def __callback_start(packed, ev, *parameters):
            start, _, _ = packed
            result = start(*parameters) if ev == event else None
            return 0 if result is None else result

        def __callback_resume(packed, ev, *parameters):
            _, resume, _ = packed
            result = resume(*parameters) if ev == event else None
            return 0 if result is None else result

        def __callback_stop(packed, ev, *parameters):
            _, _, stop = packed
            result = stop(*parameters) if ev == event else None
            return 0 if result is None else result

        # Use partial evaluation to ensure that the callbacks we
        # defined get the packed closures from our supermethod.
        callback_start, callback_resume, callback_stop = (functools.partial(closure, packed) for closure in [__callback_start, __callback_resume, __callback_stop])
        callback_packed = callback_start, callback_resume, callback_stop

        # Now we can install the start and stop callbacks in reverse because the
        # decompiler seems to treat its callbacks as-if they're stored in a stack.
        cls, module = self.__class__, self.__hexrays_module__

        # Now we can install the callbacks into the decompiler.
        if not module.install_hexrays_callback(callback_stop):
            logging.warning(u"{:s}.__attach_managers({!r}) : Unable to attach to the {:s} event with the manager callback ({:s}).".format('.'.join([__name__, cls.__name__]), event, self.__formatter__(event), internal.utils.pycompat.fullname(callback_stop)))
            return False

        # If we succeeded, then update our dictionaries.
        if module.install_hexrays_callback(callback_start) > 0:
            self.__attached__[event] = callback_packed
            self.__attached_scope[event] = callback_start, callback_stop
            self.__attached_references[event] = []
            return True

        # If not, then we need to uninstall the one that did succeed (stop) before returning our failure.
        logging.warning(u"{:s}.__attach_managers({!r}) : Unable to attach to the {:s} event with the required manager callback ({:s}).".format('.'.join([__name__, cls.__name__]), event, self.__formatter__(event), internal.utils.pycompat.fullname(callback_start)))
        expected, res = 1, module.remove_hexrays_callback(callback_stop)
        if res:
            logging.debug(u"{:s}.__attach_managers({!r}) : Removed {:d} manager callback{:s} that was attached to the {:s} event despite previous error.".format('.'.join([__name__, cls.__name__]), event, res, '' if res == 1 else 's', self.__formatter__(event)))
        else:
            logging.critical(u"{:s}.__attach_managers({!r}) : Unable to recover from the previous warning and detach the manager callback ({:s}) that is currently attached to the {:s} event.".format('.'.join([__name__, cls.__name__]), event, internal.utils.pycompat.fullname(callback_stop), self.__formatter__(event)))
        return False

    def __attach_update(self, event):
        '''Attach the required number of references to handle the specified `event`.'''
        assert(all(event in attached for attached in [self.__attached__, self.__attached_scope, self.__attached_references]))
        cls, module = self.__class__, self.__hexrays_module__

        # Confirm that the "stop" callback is actually attached.
        scope_start, scope_stop = self.__attached_scope[event]
        assert(scope_stop is not None)

        # Use our supermethod to get the number of callbacks that need to
        # be registered and the packed tuple containing those callbacks.
        count, _ = super(priorityhxevent, self).attach(event)
        cls, callback_packed = self.__class__, self.__attached__[event]
        callback_start, callback_resume, callback_stop = callback_packed

        # The "start" callback always needs to be the last one that's
        # dispatched, so we first need to remove the old instance.
        scope_start, scope_stop = self.__attached_scope[event]
        if scope_start is not None and not module.remove_hexrays_callback(scope_start):
            logging.warning(u"{:s}.__attach_update({!r}) : Unable to temporarily remove the manager callback ({:s}) that is attached to the {:s} event.".format('.'.join([__name__, cls.__name__]), event, internal.utils.pycompat.fullname(scope_start), self.__formatter__(event)))
            return False

        self.__attached_scope[event] = None, scope_stop
        logging.debug(u"{:s}.__attach_update({!r}) : Temporarily removed manager callback ({:s}) that was attached to the {:s} event.".format('.'.join([__name__, cls.__name__]), event, internal.utils.pycompat.fullname(scope_start), self.__formatter__(event)))

        # Now we can figure out whether we need to attach or detach
        # references to the callback to process the event correctly.
        references = [reference for reference in self.__attached_references[event]]

        # Older versions of the decompiler require each callable to
        # be different. We accomplish this using functools.partial.
        adding, removing = [], []
        if len(references) < count:
            while len(references) + len(adding) < count:
                reference = functools.partial(callback_resume)
                adding.append(reference)

            logging.debug(u"{:s}.__attach_update({!r}) : Created {:d} reference{:s} for the callback ({:s}) to attach to the {:s} event.".format('.'.join([__name__, cls.__name__]), event, len(adding), '' if len(adding) == 1 else 's', internal.utils.pycompat.fullname(callback_resume), self.__formatter__(event)))

        # Modify our list directly by moving a reference to the
        # callback into the list of references for us to remove.
        elif len(references) > count:
            while len(references) > count:
                reference = references.pop()
                removing.append(reference)

            logging.debug(u"{:s}.__attach_update({!r}) : Grabbed {:d} reference{:s} of the callback ({:s}) to detach from the {:s} event.".format('.'.join([__name__, cls.__name__]), event, len(adding), '' if len(adding) == 1 else 's', internal.utils.pycompat.fullname(callback_resume), self.__formatter__(event)))

        # First remove the required number of references to our callback.
        remaining = []
        for index, reference in enumerate(removing):
            if module.remove_hexrays_callback(reference) > 0:
                continue
            remaining.append(index)

        if len(remaining) != len(removing):
            logging.debug(u"{:s}.__attach_update({!r}) : Unable to remove {:d} out of {:d} callback{:s} from the {:s} event.".format('.'.join([__name__, cls.__name__]), event, len(remaining), len(removing), '' if len(removing) == 1 else 's', self.__formatter__(event)))

        references = [instance for instance in itertools.chain(references, [removing[index] for index in remaining])]
        logging.debug(u"{:s}.__attach_update({!r}) : Currently there are {:d} callback{:s} attached to the {:s} event after removal.".format('.'.join([__name__, cls.__name__]), event, len(references), '' if len(references) == 1 else 's', self.__formatter__(event)))

        # Then we can add the required number of references to our callback.
        additional = []
        for index, reference in enumerate(adding):
            if module.install_hexrays_callback(reference) > 0:
                additional.append(reference)
            continue

        if len(additional) != len(adding):
            missed = len(adding) - len(additional)
            logging.debug(u"{:s}.__attach_update({!r}) : Unable to install {:d} out of {:d} callback{:s} for the {:s} event.".format('.'.join([__name__, cls.__name__]), event, missed, len(adding), '' if len(adding) == 1 else 's', self.__formatter__(event)))

        references = [instance for instance in itertools.chain(references, additional)]
        logging.debug(u"{:s}.__attach_update({!r}) : Currently there are {:d} callback{:s} attached to the {:s} event after addition.".format('.'.join([__name__, cls.__name__]), event, len(references), '' if len(references) == 1 else 's', self.__formatter__(event)))

        # Assign all the references that were successful back into our dictionary.
        self.__attached_references[event][:] = references

        # Check that the number of references to our callbacks matches what's
        # required and try to reattach the temporarily removed callback.
        scope_start, scope_stop = self.__attached_scope[event]
        if scope_start is not None or module.install_hexrays_callback(callback_start) > 0:
            self.__attached_scope[event] = scope_start or callback_start, callback_stop

        # Otherwise something has failed and we need to log a warning and disable the event.
        references = self.__attached_references[event]
        if len(references) == count and all(callback is not None for callback in self.__attached_scope[event]):
            return True

        elif len(references) != count:
            logging.warning(u"{:s}.__attach_update({!r}) : Unable to {:s} {:d} reference{:s} to the callback ({:s}) for the {:s} event to meet the required {:d} reference{:s}.".format('.'.join([__name__, cls.__name__]), event, 'install' if successful < count else 'remove', successful, '' if successful == 1 else 's', internal.utils.pycompat.fullname(callback_resume), self.__formatter__(event), count, '' if count == 1 else 's'))

        scope_start, scope_stop = self.__attached_scope[event]
        if scope_start is None:
            logging.warning(u"{:s}.__attach_update({!r}) : Unable to re-attach the temporarily removed {:s} callback ({:s}) for the {:s} event.".format('.'.join([__name__, cls.__name__]), event, internal.utils.pycompat.fullname(scope_start or callback_start), self.__formatter__(event)))

        # Remove both the stop and start callbacks that were installed in reverse order.
        scope_start, scope_stop = self.__attached_scope[event]
        if scope_stop is not None and module.remove_hexrays_callback(scope_stop):
            self.__attached_scope[event] = scope_start, None
        else:
            logging.critical(u"{:s}.__attach_update({!r}) : Unable to recover from the previous warning and detach the manager callback ({:s}) that is currently attached to the {:s} event.".format('.'.join([__name__, cls.__name__]), event, internal.utils.pycompat.fullname(callback_stop), self.__formatter__(event)))

        scope_start, scope_stop = self.__attached_scope[event]
        if scope_start is not None and module.remove_hexrays_callback(scope_start):
            self.__attached_scope[event] = None, scope_stop
        else:
            logging.critical(u"{:s}.__attach_update({!r}) : Unable to recover from the previous warning and detach the manager callback ({:s}) that is currently attached to the {:s} event.".format('.'.join([__name__, cls.__name__]), event, internal.utils.pycompat.fullname(callback_start), self.__formatter__(event)))

        # Now we can go through through and remove all of the references that were added.
        remaining, references = [], self.__attached_references[event]
        for index, reference in enumerate(references):
            if module.remove_hexrays_callback(reference) > 0:
                continue
            remaining.append(index)

        self.__attached_references[event][:] = remaining

        # If we couldn't remove everything, then this is a critical failure and
        # we weren't able to detach all the callbacks for the specified event.
        if remaining:
            logging.critical(u"{:s}.__attach_update({!r}) : Unable to recover from the previous warning and detach {:d} of {:d} callback{:s} ({:s}) that {:s} currently attached to the {:s} event.".format('.'.join([__name__, cls.__name__]), event, len(remaining), len(references), '' if len(references) == 1 else 's', internal.utils.pycompat.fullname(callback_resume), 'is' if len(references) == 1 else 'are', self.__formatter__(event)))
        return False

    def attach(self, event):
        '''Attach to the specified `event` in order to receive them from the decompiler.'''
        cls = self.__class__
        if event not in self.__events__:
            message = '' if isinstance(event, internal.types.integer) else ' (event needs to be an integer)'
            raise NameError(u"{:s}.attach({!r}) : Unable to attach to the event {:s} due to the event being unavailable{:s}.".format('.'.join([__name__, cls.__name__]), event, self.__formatter__(event), message))

        # If the decompiler isn't ready, then we can't attach anything.
        elif not getattr(self, '__hexrays_ready__', False):
            raise internal.exceptions.UnsupportedCapability(u"{:s}.attach({!r}) : Unable to attach to the event {:s} due to the decompiler being unavailable.".format('.'.join([__name__, cls.__name__]), event, self.__formatter__(event)))

        module = self.__hexrays_module__

        # We need to get the number of references to attach from our supermethod.
        count, _ = super(priorityhxevent, self).attach(event)

        # If the event is not yet attached, then we need to use the callbacks
        # from our parent class and install only the ones that are actually relevant.
        ok = True if event in self.__attached__ else self.__attach_managers(event)

        if not ok:
            return False

        # Ensure that all our dictionaries are set for the specified event and
        # attempt to install the required number of callbacks to handle it.
        assert(all(event in attached for attached in [self.__attached__, self.__attached_scope, self.__attached_references]))
        return self.__attach_update(event)

    def __detach_remove(self, event):
        '''Remove all of the callbacks that are currently attached to the given `event`.'''
        assert(all(event in attached for attached in [self.__attached__, self.__attached_scope, self.__attached_references]))
        cls, callback_packed, module = self.__class__, self.__attached__[event], self.__hexrays_module__
        callback_start, callback_resume, callback_stop = callback_packed

        # Start out by removing the callbacks that are used to manage the scope of the event.
        scope_start, scope_stop = self.__attached_scope[event]
        if scope_start is not None and not module.remove_hexrays_callback(callback_start):
            logging.warning(u"{:s}.__detach_remove({!r}) : Unable to remove the manager callback ({:s}) that is attached to the {:s} event.".format('.'.join([__name__, cls.__name__]), event, internal.utils.pycompat.fullname(callback_start), self.__formatter__(event)))
            return False

        self.__attached_scope[event] = None, scope_stop
        logging.info(u"{:s}.__detach_remove({!r}) : Removed the manager callback ({:s}) that was attached to the {:s} event.".format('.'.join([__name__, cls.__name__]), event, internal.utils.pycompat.fullname(callback_start), self.__formatter__(event)))

        scope_start, scope_stop = self.__attached_scope[event]
        if scope_stop is not None and module.remove_hexrays_callback(callback_stop) > 0:
            logging.info(u"{:s}.__detach_remove({!r}) : Removed the manager callback ({:s}) that was attached to the {:s} event.".format('.'.join([__name__, cls.__name__]), event, internal.utils.pycompat.fullname(callback_stop), self.__formatter__(event)))
            self.__attached_scope[event] = scope_start, None

        elif scope_stop is not None:
            logging.warning(u"{:s}.__detach_remove({!r}) : Unable to remove the manager callback ({:s}) that is attached to the {:s} event.".format('.'.join([__name__, cls.__name__]), event, internal.utils.pycompat.fullname(callback_stop), self.__formatter__(event)))

        # Now we need to go through and remove as many references as we can.
        remaining, available = [], self.__attached_references[event]
        for index, callback in enumerate(available):
            if module.remove_hexrays_callback(callback) > 0:
                continue
            remaining.append(index)

        count, self.__attached_references[event][:] = len(available), [available[index] for index in remaining]

        # If we couldn't remove everything, then log a warning and return a failure.
        if remaining or any(callback is not None for callback in self.__attached_scope[event]):
            logging.warning(u"{:s}.__detach_remove({!r}) : Unable to remove {:d} of {:d} callback{:s} that {:s} attached to the {:s} event.".format('.'.join([__name__, cls.__name__]), event, len(remaining), count, '' if count == 1 else 's', 'is' if count == 1 else 'are', self.__formatter__(event)))
        return not remaining and all(callback is None for callback in self.__attached_scope[event])

    def detach(self, event):
        '''Detach from the specified `event` so that they will not be received by the decompiler.'''
        cls = self.__class__
        if event not in self.__events__:
            message = '' if isinstance(event, internal.types.integer) else ' (event needs to be an integer)'
            raise NameError(u"{:s}.detach({!r}) : Unable to detach from the {:s} event due to the event being unavailable{:s}.".format('.'.join([__name__, cls.__name__]), event, self.__formatter__(event), message))

        # If it's not connected, then we need to freak out at the user.
        if event not in self.__attached__:
            logging.warning(u"{:s}.detach({!r}) : Unable to detach from the {:s} event as it is not currently attached.".format('.'.join([__name__, cls.__name__]), event, self.__formatter__(event)))
            return False

        # If the decompiler isn't ready, then we're unable to do anything.
        elif not getattr(self, '__hexrays_ready__', False):
            raise internal.exceptions.UnsupportedCapability(u"{:s}.detach({!r}) : Unable to detach from the event {:s} due to the decompiler being unavailable.".format('.'.join([__name__, cls.__name__]), event, self.__formatter__(event)))

        # Then we can remove all of the decompiler-related callbacks.
        if not self.__detach_remove(event):
            return False

        # If there's still any references that are attached, then log something
        # about it and fail because we don't have another way to clean this up.
        elif self.__attached_references[event]:
            logging.warning(u"{:s}.detach({!r}) : Unable to detach {:d} callback{:s} that are still installed for the {:s} event.".format('.'.join([__name__, cls.__name__]), event, len(self.__attached_references[event]), '' if len(self.__attached_references[event]) == 1 else 's', self.__formatter__(event)))
            return False

        # Everything should be removed, so we now only need to remove references.
        count = self.__attached_references.pop(event)
        callback_packed = self.__attached__.pop(event)
        del(callback_packed)

        # Now we can finish everything up with our detach supermethod.
        return super(priorityhxevent, self).detach(event)

    def close(self):
        '''Remove all of the events that are currently attached.'''
        cls = self.__class__
        if not super(priorityhxevent, self).close():
            logging.critical(u"{:s}.close() : Error trying to detach from all of the events that are attached.".format('.'.join([__name__, cls.__name__])))
            [logging.debug(u"{:s}.close() : Event {:s} is still attached{:s}.".format('.'.join([__name__, cls.__name__]), self.__formatter__(event), " by {:d} callback{:s}".format(len(self.__attached_references[event]), '' if len(self.__attached_references[event]) == 1 else 's') if event in self.__attached__ else '')) for event in self]

        # We only fail here if our state is not empty.
        return False if self.__attached__ else True

    def add(self, event, callable, priority=0):
        '''Add the `callable` to the queue with the given `priority` for the specified `event`.'''
        cls = self.__class__

        # If the plugin isn't ready, then simulate an attach and add it.
        if not getattr(self, '__hexrays_ready__', False):
            return super(priorityhxevent, self).add(event, callable, priority)

        # Attach to the event so that we can actually do stupid things with it.
        if not self.attach(event):
            raise internal.exceptions.DisassemblerError(u"{:s}.add({:#x}, {!s}, {:+d}) : Unable to attach to the {:s} event.".format('.'.join([__name__, cls.__name__]), event, callable, priority, self.__formatter__(event)))

        # Add the callable to our current events to call.
        return super(priorityhxevent, self).add(event, callable, priority)

    def __repr__(self):
        message = 'attached' if getattr(self, '__hexrays_ready__', False) else 'being monitored (decompiler not loaded)'
        if len(self):
            res, items = "Events currently {:s}:".format(message), super(priorityhxevent, self).__repr__().split('\n')
            return '\n'.join([res] + items[1:])
        return "Events currently {:s}: {:s}".format(message, 'No events are being monitored.')

    ## Callbacks to enable class when the decompiler plugin has been loaded.
    __plugin_required = {'Hex-Rays Decompiler'}
    def __plugin_loaded__(self, plugin_info):
        cls, plugin_name = self.__class__, internal.utils.string.of(plugin_info.name)
        if plugin_name not in self.__plugin_required:
            return

        module = self.__hexrays_module__

        # Initialize the hexrays plugin so that we be sure that it's usable.
        logging.debug(u"{:s} : Initializing the Hex-Rays plugin with `{:s}` due to receiving a plugin loaded event for \"{:s}\".".format('.'.join([__name__, cls.__name__]), internal.utils.pycompat.fullname(module.init_hexrays_plugin), internal.utils.string.escape(plugin_name, '"')))
        if not module.init_hexrays_plugin():
            cls = self.__class__
            raise internal.exceptions.DisassemblerError(u"{:s} : Failure while trying initialize the Hex-Rays plugin with `{:s}`.".format('.'.join([__name__, cls.__name__]), internal.utils.pycompat.fullname(module.init_hexrays_plugin)))

        # Assign our protected properties that enable the class to do things.
        self.__hexrays_module__ = module
        self.__hexrays_ready__ = True

        # Now we can attach all currently monitored events.
        logging.debug(u"{:s} : Attaching {:d} event{:s} for the Hex-Rays plugin due to receiving a plugin loaded event for \"{:s}\".".format('.'.join([__name__, cls.__name__]), len(self), '' if len(self) == 1 else 's', internal.utils.string.escape(plugin_name, '"')))
        for event in self:
            if not self.attach(event):
                logging.warning(u"{:s} : Unable to attach the {:s} event during the loading process of the Hex-Rays plugin.".format('.'.join([__name__, cls.__name__]), self.__formatter__(event)))
            continue
        return

    def __plugin_unloading__(self, plugin_info):
        cls, plugin_name = self.__class__, internal.utils.string.of(plugin_info.name)
        if plugin_name not in self.__plugin_required:
            return

        # Go through and detach everything that we're monitoring.
        logging.debug(u"{:s} : Detaching {:d} event{:s} for the Hex-Rays plugin due to receiving a plugin unloaded event for \"{:s}\".".format('.'.join([__name__, cls.__name__]), len(self), '' if len(self) == 1 else 's', internal.utils.string.escape(plugin_name, '"')))
        for event in self:
            if not self.detach(event):
                logging.warning(u"{:s} : Unable to detach the {:s} event during the unloading process of the Hex-Rays plugin.".format('.'.join([__name__, cls.__name__]), self.__formatter__(event)))
            continue

        # Now we can modify our state that disables our class.
        self.__hexrays_ready__ = False

class priorityaction(prioritybase):
    """
    Helper class for allowing one to register and unregister actions within the
    disassembler and attach a callable to it when the action is activated.

    To register an action, the `priorityaction.new` method must be called with
    the action name, its scope, a dictionary containing the attributes to match,
    and any other attributes that the action should have. The name of the action
    and its scope are both required to register an action. The available scopes
    are:

        * "application" - Available while the application is running.
        * "database" - Available only within the current database.
        * "widget" - Available only within the widget it is attached to.

    The following attributes can be used when registering a new action:

        * `label` - The label of the action, defaults to name if not provided.
        * `shortcut` - The keyboard shortcut(s) associated with the action.
        * `tooltip` - The tooltip that the disassembler will display.
        * `icon` - An integer containing the icon to display.

    After the action has been registered, a callable can be attached to it using
    the `priorityaction.add` method. Activation of the action will then result
    in executing the callables that are attached.
    """

    # convert an action_handler_t.update method result to a description.
    __action_state_description__ = {
        idaapi.AST_ENABLE_FOR_IDB: 'ENABLE_FOR_DATABASE',
        idaapi.AST_ENABLE: 'ENABLE_FOR_APPLICATION',
        idaapi.AST_DISABLE_FOR_IDB: 'DISABLE_FOR_DATABASE',
        idaapi.AST_DISABLE: 'DISABLE_FOR_APPLICATION',
    }

    # create a dictionary for looking up the potential action update results.
    __action_state_mapping__ = {
        'APPLICATION': (idaapi.AST_ENABLE, idaapi.AST_DISABLE),
        'DATABASE': (idaapi.AST_ENABLE_FOR_IDB, idaapi.AST_DISABLE_FOR_IDB),
    }

    # update the dicts we just defined the correct widget-related result.
    if hasattr(idaapi, 'AST_ENABLE_FOR_FORM') and hasattr(idaapi, 'AST_DISABLE_FOR_FORM'):
        __action_state_description__[idaapi.AST_ENABLE_FOR_FORM] = 'ENABLE_FOR_WIDGET'
        __action_state_description__[idaapi.AST_DISABLE_FOR_FORM] = 'DISABLE_FOR_WIDGET'

        __action_state_mapping__['WIDGET'] = (idaapi.AST_ENABLE_FOR_FORM, idaapi.AST_DISABLE_FOR_FORM)

    else:
        __action_state_description__[idaapi.AST_ENABLE_FOR_WIDGET] = 'ENABLE_FOR_WIDGET'
        __action_state_description__[idaapi.AST_DISABLE_FOR_WIDGET] = 'DISABLE_FOR_WIDGET'

        __action_state_mapping__['WIDGET'] = (idaapi.AST_ENABLE_FOR_WIDGET, idaapi.AST_DISABLE_FOR_WIDGET)

    # define a dictionary that can be used for checking the attribute types for
    # an action descriptor. we also keep a list that's used to match an
    # attribute by name to its idaapi.action_desc_t parameter number.
    __action_attribute_types__ = {
        'name': internal.types.string,
        'label': internal.types.string,
        'shortcut': internal.types.string,
        'tooltip': internal.types.string,
        'icon': internal.types.integer,
        'state': internal.types.integer,
        'checkable': internal.types.bool,
        'checked': internal.types.bool,
        'visibility': internal.types.bool,
    }

    __action_attribute_order__ = ['name', 'label', 'handler', 'shortcut', 'tooltip', 'icon', 'flags']

    ## that should be all of our tables.

    # FIXME: we should also track the shortcuts for each action too, so that we
    #        can complain about it if there's a duplicate. it's worth knowing
    #        that we can also interact with shortcuts for actions that we did
    #        not register ourselves.

    def __init__(self):
        super(priorityaction, self).__init__()

        # dictionaries containing descriptors and how to instantiate them.
        self.__descriptors__ = {}           # action_desc_t
        self.__descriptor_params__ = {}     # parameters for action_desc_t

        # dictionaries containing the instantiated actions by their name.
        self.__handlers__ = {}              # action_handler_t
        self.__action_scope__ = {}          # matching scope (widget, idb, app)

        # a dictionary containing the actions that have been registered
        # and what attributes for idaapi.action_ctx_base_t to match for.
        self.__registration__ = {}          # matching dict

        # a dictionary containing the callables to register for activation.
        # these are used when enabling an action, or disabling it. this doesn't
        # really make sense for actions, but we need this because that's just
        # how our parent class works.
        self.__handler_scope__ = {}

    def __formatter__(self, action_name):
        return "\"{:s}\"".format(internal.utils.string.escape(action_name, '"'))

    def __new_action_handler(self, action, callbacks):
        '''Return an ``idaapi.action_handler_t`` class for executing the specified `action`.'''
        packed = callbacks

        # define a base class that our new class will inherit from.
        class handler_t(idaapi.action_handler_t):
            '''This class is used to implement the action for a handler.'''

            def __repr__(self):
                return "{:s}<{:s}>".format('action_handler_t', action)

        handler_t.__name__ = "{:s}<{:s}>".format(handler_t.__name__, action)

        # first we'll define the activation method. this is the method that's
        # actually responsible for executing the callable(s) attached to the
        # registered action.
        def handler_activate(action_name, packed):
            start, stop, resume = packed

            # Even though you can only attach one callable to an action, we have
            # 3 of them where each can return a result of some sort. We need to
            # execute each callable and figure out which result to return.
            def handler_activate_closure(self, context):
                wants_refresh = 0

                # Start everything and snag the first result. This result is
                # used to tell the disassembler whether the affected views
                # should be refreshed.
                res = start(context)
                wants_refresh = wants_refresh if res is None else res

                # Now we can resume any others if they were attached. We track
                # the result and assign it to "wants_refresh", but we only
                # overwrite the previous value if it's non-zero.
                res = resume(context)
                if res is not None:
                    wants_refresh = max(wants_refresh, res)

                # To close everything out, we do the same thing and return our
                # result of whether one of the callbacks wanted to refresh.
                res = stop(context)
                if res is not None:
                    wants_refresh = max(wants_refresh, res)
                return wants_refresh
            return handler_activate_closure

        # next we need the handler method that will be responsible for doing the
        # actual selection against whatever context it's given. This takes the
        # action mapping type which distinguishes whether the action is scoped
        # to the database, widget, or the application (always).
        def handler_update(action_name, packed):
            mapping_scope = self.__action_scope__[action_name]
            match_attributes = self.__registration__[action_name]

            # this is just to capture any attributes that aren't associated with
            # an idaapi.action_ctx_base_t. the method gets called repeatedly, so
            # we only want to log the missing attributes only once.
            warnings = []

            # here is the method that we're going to use for matching.
            yes, no = self.__action_state_mapping__[mapping_scope.upper()]
            def handler_update_closure(self, context):
                for attribute, check in match_attributes.items():
                    if not hasattr(context, attribute):
                        if warnings:
                            continue

                        # if the attribute didn't exist, then enumerate all the
                        # ones that might be missing and log a warning for it.
                        missing = sorted({missing for missing in match_attributes if not hasattr(context, missing)})
                        logging.info(u"{:s}.update({!r}) : Some of the attributes requested to be matched do not exist ({:s}) and will be ignored.".format('.'.join([__name__, cls.__name__]), action_name, context, ', '.join(missing)))
                        warnings.append(missing)
                        continue

                    # We found an attribute that we can use. Grab its value and
                    # check against the callable to identify whether it matches.
                    value = getattr(context, attribute)
                    if callable(check) and check(value):
                        return yes

                    # The match isn't a callable, which instead requires us to
                    # compare the value to see if it's an actual match.
                    elif isinstance(check, internal.types.unordered) and value in check:
                        return yes

                    elif value == check:
                        return yes
                    continue
                return no
            return handler_update_closure

        # Now we can create an action_handler_t with our methods attached.
        namespace = {}
        namespace['activate'] = handler_activate(action, packed)
        namespace['update'] = handler_update(action, packed)
        action_t = type("action_handler_t({:s})".format(action), (handler_t,), namespace)

        # The class should now be ready for instantiation and can be attached.
        return action_t

    ### parent class
    def attach(self, name):
        '''Register the action with the specified `name` and attach any callables from its queue.'''
        cls = self.__class__

        # If the handler already exists, then the action was already attached.
        if name in self.__handlers__:
            logging.debug(u"{:s}.attach({!r}) : The action \"{:s}\" has already been attached and is currently being handled.".format('.'.join([__name__, cls.__name__]), name, internal.utils.string.escape(name, '"')))
            return True

        # Verify that we haven't attached any packed callables for this action.
        elif name in self.__handler_scope__:
            logging.debug(u"{:s}.attach({!r}) : The action \"{:s}\" has already been attached and is currently being handled.".format('.'.join([__name__, cls.__name__]), name, internal.utils.string.escape(name, '"')))
            return True

        # Ensure that the descriptor was properly added to our dictionary.
        elif name not in self.__descriptor_params__:
            logging.warning(u"{:s}.attach({!r}) : The action \"{:s}\" cannot be attached as it has not yet been registered.".format('.'.join([__name__, cls.__name__]), name, internal.utils.string.escape(name, '"')))
            return False

        # Grab our callables from the parent class, and stash a ref for them.
        # Then we can use them to get an action_handler_t and attach an instance
        # instance of it to the action_desc_t that we need for registration.
        count, packed = super(priorityaction, self).attach(name)
        action_handler_t = self.__new_action_handler(name, packed)
        handler = action_handler_t()

        # Now we can get the parameters used to instantiate the action_desc_t
        # and add our callback into its list. Afterwards, we only need to try to
        # register it and stash the descriptor if we were succesful.
        parameters = self.__descriptor_params__[name]

        if parameters[2] is not None:
            cls = self.__class__
            logging.warning(u"{:s}.attach({!r}) : Overwriting the user-specified callback ({!s}) with a new one.".format('.'.join([__name__, cls.__name__]), name, parameters[2], handler))
        parameters[2] = handler

        # FIXME: should probably describe more information about the action when
        #        we're logging a critical failure.
        descriptor = idaapi.action_desc_t(*parameters)
        if not idaapi.register_action(descriptor):
            logging.critical(u"{:s}.attach({!r}) : Unable to register the action \"{:s}\" due to the disassembler returning an error.".format('.'.join([__name__, cls.__name__]), name, name))
            return False

        # It registered and we can just stash everything that was constructed.
        self.__descriptors__[name] = descriptor
        self.__handler_scope__[name] = packed
        self.__handlers__[name] = handler
        return True

    def detach(self, name):
        '''Unregister the action with the specified `name` and detach any callables associated with it.'''
        cls = self.__class__

        # If there's no handler, then the action was never attached.
        if name not in self.__handlers__:
            logging.warning(u"{:s}.detach({!r}) : The action \"{:s}\" cannot be detached as it is not currently attached.".format('.'.join([__name__, cls.__name__]), name))
            return False

        # Check for the action descriptor, because we can't detach it if the
        # descriptor wasn't allocated for it.
        elif name not in self.__descriptors__:
            logging.warning(u"{:s}.detach({!r}) : The action \"{:s}\" cannot be detached as its descriptor was never registered.".format('.'.join([__name__, cls.__name__]), name))
            return False

        # Verify that we haven't attached any packed callbacks for this action.
        elif name not in self.__handler_scope__:
            logging.warning(u"{:s}.detach({!r}) : The handlers for the action \"{:s}\" have already been removed.".format('.'.join([__name__, cls.__name__]), name))

        # Now we can try to unregister the action.
        if not idaapi.unregister_action(name):
            logging.critical(u"{:s}.detach({!r}) : Unable to unregister the action \"{:s}\" due to the disassembler returning an error.".format('.'.join([__name__, cls.__name__]), name, name))
            return False

        # Remove the action from our attachment dictionaries, and delete them to
        # ensure that there aren't any references left hanging.
        descriptors = [descriptor_dictionary.pop(name, None) for descriptor_dictionary in [self.__descriptors__, self.__descriptor_params__]]
        handlers = [handler_dictionary.pop(name, None) for handler_dictionary in [self.__handlers__, self.__action_scope__, self.__handler_scope__]]
        registration = self.__registration__.pop(name, None)

        del(descriptors, handlers, registration)

        # Now we can finish the removal by telling our parent class.
        return super(priorityaction, self).detach(name)

    def close(self):
        '''Remove all of the actions that have been attached and registered.'''
        cls, ok = self.__class__, super(priorityaction, self).close()
        if not ok:
            count = len(self.__descriptors__)
            logging.warning(u"{:s}.close() : Error trying to detach from {:d} action{:s} still remaining.".format('.'.join([__name__, cls.__name__]), count, ' that is' if count == 1 else 's that are', count))

        # If our parent class couldn't close all the actions, figure out which
        # descriptors exist and complain about it before returning False.
        if not ok:
            for name in sorted(self.__descriptors__):
                if name in self.__handler_scope__:
                    logging.debug(u"{:s}.close() : Detaching action {:s} resulted in its callbacks remaining attached.".format('.'.join([__name__, cls.__name__]), self.__formatter__(name)))

                elif name in self.__handlers__:
                    logging.debug(u"{:s}.close() : Detaching action {:s} resulted in its handler still remaining instantiated ({!s}).".format('.'.join([__name__, cls.__name__]), self.__formatter__(name), self.__handlers__[name]))

                elif name in self.__registration__:
                    logging.debug(u"{:s}.close() : Detaching action {:s} resulted in its match dictionary not being removed ({!s}).".format('.'.join([__name__, cls.__name__]), self.__formatter__(name), self.__registration__[name]))

                elif name in self.__descriptor_params__:
                    logging.debug(u"{:s}.close() : Detaching action {:s} resulted in its desciptor parameters not being removed.".format('.'.join([__name__, cls.__name__]), self.__formatter__(name)))

                elif name in self.__action_scope__:
                    logging.debug(u"{:s}.close() : Detaching action {:s} resulted in its scope description ({!r}) not being removed.".format('.'.join([__name__, cls.__name__]), self.__formatter__(name), self.__action_scope__[name]))

                else:
                    logging.debug(u"{:s}.close() : Detaching action {:s} resulted in its action descriptor not being destroyed.".format('.'.join([__name__, cls.__name__]), self.__formatter__(name)))
                continue
            return False

        # At this point our state should be pretty empty. If it isn't though,
        # then something critical happened and we need to scream about it.
        if self.__handler_scope__:
            actions = len(self.__handler_scope__)
            count = sum((1 for item in callbacks) for action, callbacks in self.__handler_scope__.items())
            logging.critical(u"{:s}.close() : Error trying to release {:d} callback{:s} from {:d} remaining action{:s}.".format('.'.join([__name__, cls.__name__]), count, '' if count == 1 else 's', actions, '' if actions == 1 else 's'))

            for name in sorted(self.__handler_scope__):
                logging.info(u"{:s}.close() : Detaching action {:s} resulted in its callbacks remaining attached.".format('.'.join([__name__, cls.__name__]), self.__formatter__(name)))

        if self.__handlers__:
            for name in self.__handlers__:
                logging.info(u"{:s}.close() : Detaching action {:s} resulted in its handler still remaining instantiated ({!s}).".format('.'.join([__name__, cls.__name__]), self.__formatter__(name), self.__handlers__[name]))

        if self.__registration__:
            for name in self.__registration__:
                logging.info(u"{:s}.close() : Detaching action {:s} resulted in its match dictionary not being removed ({!s}).".format('.'.join([__name__, cls.__name__]), self.__formatter__(name), self.__registration__[name]))

        if self.__descriptor_params__:
            for name in self.__descriptor_params__:
                logging.info(u"{:s}.close() : Detaching action {:s} resulted in its desciptor parameters not being removed.".format('.'.join([__name__, cls.__name__]), self.__formatter__(name)))

        if self.__action_scope__:
            for name in self.__action_scope__:
                logging.info(u"{:s}.close() : Detaching action {:s} resulted in its scope description ({!r}) not being removed.".format('.'.join([__name__, cls.__name__]), self.__formatter__(name), self.__action_scope__[name]))

        if self.__descriptors__:
            for name in self.__descriptors__:
                logging.info(u"{:s}.close() : Detaching action {:s} resulted in its action descriptor not being destroyed.".format('.'.join([__name__, cls.__name__]), self.__formatter__(name)))

        return True

    def __repr__(self):
        if len(self):
            res, items = 'Actions currently being managed:', super(priorityaction, self).__repr__().split('\n')
            return '\n'.join([res] + items[1:])
        return "Actions currently being managed: {:s}".format('No actions are being managed.')

    def list(self, *pattern, **shortcut):
        """List all of the managed and unmanaged actions for the given `pattern` with their callable and matching dictionary.

        If a glob is passed as `shortcut`, then only the actions with shortcuts
        that match will be listed.
        """
        unmanaged = [internal.utils.string.of(action) for action in idaapi.get_registered_actions()]
        managed = [action for action in self.__descriptor_params__]

        # If we were given a pattern, then filter both of our lists using it.
        if pattern:
            unmanaged = [action for action in fnmatch.filter(unmanaged, *pattern)]
            managed = [action for action in fnmatch.filter(managed, *pattern)]

        # If we were given a shortcut pattern, then generate a callable for
        # matching it depending on whatever the given type was.
        if 'shortcut' in shortcut and isinstance(shortcut['shortcut'], internal.types.string):
            regex = re.compile(fnmatch.translate(shortcut['shortcut']), re.IGNORECASE)
            Fmatch_shortcut = (lambda regex: lambda shortcut: True if regex.match(shortcut) else False)(regex)
            filter_shortcut = True

        elif 'shortcut' in shortcut and isinstance(shortcut['shortcut'], (internal.types.bool, internal.types.integer)):
            Fmatch_shortcut = (lambda boolean: lambda shortcut: boolean == (True if shortcut else False))(True if shortcut['shortcut'] else False)
            filter_shortcut = True

        else:
            Fmatch_shortcut = lambda shortcut: True
            filter_shortcut = False

        # Figure out the column size of all the available actions for alignment.
        iterable = itertools.chain([''], unmanaged, managed)
        column_unmanaged = max(len(action) + 1 for action in iterable)

        # Before displaying anything, we need to know the column sizes for
        # everything. This requires us to do a pass through our actions and the
        # actions that we don't manage.
        items, columns = [], {name: 0 for name in ['name', 'label', 'shortcut', 'scope', 'description']}
        for action in managed:
            desc = self.__descriptors__[action]
            scope = self.__action_scope__[action]
            match = self.__registration__[action]

            # Extract the fields from the descriptor, and format the match
            # dictionary so that it's a little bit more user-friendly. We also
            # split the shortcuts into their individual key combinations.
            fields = ['name', 'label', 'shortcut']
            iterable = ((attribute, getattr(desc, attribute)) for attribute in fields)
            name, label, shortcut = (internal.utils.string.of(value) for _, value in iterable)
            description = self.__describe_context_match(match)
            shortcuts = shortcut.replace(' ', '').split(',')

            # Check the shortcuts. If none of the shortcuts match, then we can
            # skip doing anything with this action. Otherwise, filter the
            # shortcuts so that we can display only the actions that match.
            if filter_shortcut and not any(map(Fmatch_shortcut, shortcuts)):
                continue
            shortcuts = [shortcut for shortcut in filter(Fmatch_shortcut, shortcuts)]

            # Now we grab the lengths that we'll need for aligning things into columns.
            columns['name'] = max(1 + len(name), columns['name']) if name else columns['name']
            columns['scope'] = max(len(scope), columns['scope'])
            columns['label'] = max(2 + len(label), columns['label']) if label else columns['label']
            columns['description'] = max(len(description), columns['description'])

            shortcut_length = max(2 + len(shortcut) for shortcut in shortcuts) if shortcuts else columns['shortcut']
            columns['shortcut'] = max(shortcut_length, columns['shortcut'])

            # That was it. We have all our attributes. We need to add a row for
            # each individual shortcut if an action has multiple registered.
            [items.append((name, scope, label, shortcut, description)) for shortcut in shortcuts]

        # Now we need to process the unmanaged actions. We need to extract the
        # same attributes for our own actions so that it looks okay.
        unmanaged_items, columns['tooltip'], columns['description'] = [], 0, max(len('<unmanaged>'), columns['description'])
        for action in unmanaged:
            if action in managed:
                continue

            # Extract all of the attributes for the current action. We also
            # split up the shortcuts since they're comma-delimited.
            state = idaapi.get_action_state(action)
            _, state = state if isinstance(state, tuple) else (True, state)
            scope = self.__action_state_description__[state].upper() if state in self.__action_state_description__ else "{:#x}".format(state) if state else ''
            label = internal.utils.string.of(idaapi.get_action_label(action))
            shortcut = internal.utils.string.of(idaapi.get_action_shortcut(action))
            tooltip = internal.utils.string.of(idaapi.get_action_tooltip(action))
            shortcuts = shortcut.replace(' ', '').split(',')

            # Next up is to check the shortcuts to see if any of them match. If
            # none of them match, then we skip this action. Otherwise, we need
            # to filter the shortcuts so we only display the matching ones.
            if filter_shortcut and not any(map(Fmatch_shortcut, shortcuts)):
                continue
            shortcuts = [shortcut for shortcut in filter(Fmatch_shortcut, shortcuts)]

            # Now we grab the lengths and preserve everything that we captured.
            columns['name'] = max(1 + len(action), columns['name']) if action else columns['name']
            columns['scope'] = max(len(scope), columns['scope'])
            columns['label'] = max(2 + len(label), columns['label']) if label else columns['label']

            # The tooltip is special though, because we don't want it to align
            # with the matching dictionary for the actions that we manage.
            columns['tooltip'] = max(2 + len(tooltip), columns['tooltip']) if tooltip else columns['tooltip']

            # As multiple shortcuts can be assign to an action, we need to
            # extract them from the action and add a row for each one found.
            shortcut_length = max(2 + len(keycombo) for keycombo in shortcuts) if shortcuts else columns['shortcut']
            columns['shortcut'] = max(shortcut_length, columns['shortcut'])

            # Then we add a row for each shortcut that we found.
            [unmanaged_items.append((action, scope, label, shortcut, tooltip)) for shortcut in shortcuts]

        # Now we just need to output everything and hope it fits. We start with
        # the managed actions, and then we can follow up with the managed ones.
        for name, scope, label, shortcut, tooltip in unmanaged_items:
            name_formatted = name
            label_formatted = "\"{:s}\"".format(label) if label else ''
            scope_formatted = scope
            shortcut_formatted = "\"{:s}\"".format(shortcut) if shortcut else ''

            six.print_(u"{:<{:d}s} {:>{:d}s} : {:<{:d}s} {:>{:d}s}".format(name_formatted, columns['name'], shortcut_formatted, columns['shortcut'], scope_formatted, columns['scope'], '<unmanaged>', columns['description']))

        for name, scope, label, shortcut, description in items:
            name_formatted = name
            label_formatted = "\"{:s}\"".format(label) if label else ''
            scope_formatted = scope
            shortcut_formatted = "\"{:s}\"".format(shortcut) if shortcut else ''

            six.print_(u"{:<{:d}s} {:>{:d}s} : {:<{:d}s} {:<{:d}s}".format(name_formatted, columns['name'], shortcut_formatted, columns['shortcut'], scope_formatted, columns['scope'], description, columns['description']))
        return

    @property
    def available(self):
        '''Return the actions that have been registered and are being managed.'''
        return { action for action in self.__descriptor_params__}

    def __describe_context_match(self, match):
        '''Describe the dictionary in `match` and return the description formatted as a string.'''
        context_t, ignored = idaapi.action_ctx_base_t, {'thisown'}

        # if our order attribute exists, then use it to format the match dict.
        if hasattr(self, '__describe_context_order__'):
            ordered = self.__describe_context_order__

            # now we'll use the order to gather the pairs in the match dictionary,
            # and then we can figure out how to render each field.
            fields = [(attribute, match[attribute]) for attribute in ordered if attribute in match]

            descriptions = []
            for key, value in fields:
                descriptions.append((key, self.__repr_object__(value)))

            # next we'll format our descriptions into a single-line description.
            format = "match({:s})".format
            return format(', '.join("{:s}={!s}".format(key, value) for key, value in descriptions))

        # start out by gathering all the available attributes we can match with,
        # and then order them in the way that they'll be displayed.
        iterable = ((attribute, getattr(context_t, attribute)) for attribute in dir(context_t))
        filtered = ((attribute, value) for attribute, value in iterable if not attribute.startswith('__'))
        iterable = ((attribute, value) for attribute, value in filtered if not callable(value))
        unordered = {attribute for attribute, _ in iterable} - ignored
        ordered = ['action', 'widget_type', 'widget_title']
        ordered += [attribute for attribute in sorted(unordered) if attribute not in ordered]

        # we're done, so we just need to save these results in our object and
        # then we can recurse to describe the match dictionary.
        self.__describe_context_order__ = ordered
        return self.__describe_context_match(match)

    def new(self, name, scope, *match, **attributes):
        """Create an action with the specified `name` and `scope` where the attributes of the context match the dictionary in `match`.

        This method will initialize an action of the `scope` specified as a
        string. The `match` dictionary will be used to match the attributes of
        the ``idaapi.action_ctx_base_t`` that is provided by the disassembler.

        The `label` and `tooltip` attributes take a string.
        The `icon` and `flag` attributes both will take an integer.
        The `shortcut` attribute can take a string or a list of strings.
        """
        attributes_description = internal.utils.string.kwargs(attributes)
        available_attributes = {
            'name', 'label',
            'shortcut', 'tooltip', 'icon',
            'flags',
        }

        attribute_defaults = {
            'name': name, 'label': name,
            'handler': None, 'shortcut': None, 'tooltip': None, 'icon': -1, 'flags': 0,
        }

        # Start out by checking whether we were given a scope and dictionary, or
        # just the dictionary. This way the dictionary is always going to be
        # required, and we can give it a default of "APPLICATION" for the scope.
        if len(match) not in {0, 1}:
            cls, attributes_description = self.__class__, ", {:s}".format(attributes_description) if attributes else ''
            raise internal.exceptions.InvalidParameterError(u"{:s}.new({!r}, {!r}{:s}{:s}) : Unable to add a new action without a dictionary to match attributes with.".format('.'.join([__name__, cls.__name__]), name, scope, ", {:s}".format(', '.join(map("{!r}".format, match))) if match else '', attributes_description, ', '.join(unavailable)))

        [scope, match] = itertools.chain([scope], match) if match else ('APPLICATION', scope)

        # Now we'll need to validate the parameters we were given.
        if name in self.__descriptors__:
            cls, attributes_description = self.__class__, ", {:s}".format(attributes_description) if attributes else ''
            raise internal.exceptions.DuplicateItemError(u"{:s}.new({!r}, {!r}, ...{:s}) : Unable to add a new action due to one with the name \"{:s}\" already existing.".format('.'.join([__name__, cls.__name__]), name, scope, attributes_description, internal.utils.string.escape(name, '"')))

        elif any(key not in available_attributes for key in attributes):
            cls, attributes_description = self.__class__, ", {:s}".format(attributes_description) if attributes else ''
            unavailable = [key for key in attributes if key not in available_attributes]
            raise internal.exceptions.InvalidParameterError(u"{:s}.new({!r}, {!r}, ...{:s}) : Unable to add a new action with the requested attributes due to some of them being unavailable ({:s}).".format('.'.join([__name__, cls.__name__]), name, scope, attributes_description, ', '.join(unavailable)))

        elif not isinstance(scope, internal.types.string):
            cls, attributes_description = self.__class__, ", {:s}".format(attributes_description) if attributes else ''
            raise internal.exceptions.UnsupportedCapability(u"{:s}.new({!r}, {!r}, ...{:s}) : Unable to add the specified action (\"{:s}\") due to its scope ({!r}) being of an unsupported type ({!s}).".format('.'.join([__name__, cls.__name__]), name, scope, attributes_description, internal.utils.string.escape(name, '"'), scope, scope.__class__))

        elif scope.upper() not in self.__action_state_mapping__:
            cls, attributes_description = self.__class__, ", {:s}".format(attributes_description) if attributes else ''
            raise internal.exceptions.UnsupportedCapability(u"{:s}.new({!r}, {!r}, ...{:s}) : Unable to add the specified action (\"{:s}\") due to its scope ({!r}) being unsupported.".format('.'.join([__name__, cls.__name__]), name, scope, attributes_description, internal.utils.string.escape(name, '"'), scope))

        elif not isinstance(match, internal.types.dictionary):
            cls, attributes_description = self.__class__, ", {:s}".format(attributes_description) if attributes else ''
            raise internal.exceptions.InvalidParameterError(u"{:s}.new({!r}, {!r}, ...{:s}) : Unable to add a new action due to the matching dictionary ({!r}) being of an unsupported type ({!s}).".format('.'.join([__name__, cls.__name__]), name, scope, attributes_description, match, match.__class__))

        # Before we do any type-checking, we need to check if the shortcut we
        # were given is a string or an unordered container. If it's an unordered
        # container and it only contains strings, then we can join each key
        # combination with a ',' to map multiple shortcuts to the action.
        if isinstance(attributes.get('shortcut'), internal.types.unordered):
            if not all(isinstance(item, internal.types.string) for item in attributes['shortcut']):
                cls, attributes_description = self.__class__, ", {:s}".format(attributes_description) if attributes else ''
                invalid = [item.__class__ for item in attributes['shortcut'] if not isinstance(item, internal.types.string)]
                expected_packed = self.__action_attribute_types__['shortcut']
                expected = next(iter(expected_packed)) if hasattr(expected_packed, '__iter__') else expected_packed
                raise internal.exceptions.InvalidParameterError(u"{:s}.new({!r}, {!r}, ...{:s}) : Unable to add a new action due to the \"{:s}\" attribute containing {:s} ({!s}) than what was expected ({!s}).".format('.'.join([__name__, cls.__name__]), name, scope, attributes_description, internal.utils.string.escape('shortcut', '"'), 'a different type' if len(invalid) == 1 else 'different types', ', '.join(map("{!s}".format, invalid)), expected))
            attributes['shortcut'] = ','.join(attributes['shortcut'])

        # We'll need to do proper type-checking here to avoid a potential error
        # occurring when we try later to attach the action to an action_desc_t.
        invalid = []
        for key, value in attributes.items():
            expected = self.__action_attribute_types__[key]
            if not isinstance(value, expected):
                invalid.append((key, value, expected))
            continue

        if invalid:
            cls, attributes_description = self.__class__, ", {:s}".format(attributes_description) if attributes else ''
            key, value, expected_packed = invalid[0]
            expected = next(iter(expected_packed)) if hasattr(expected_packed, '__iter__') else expected_packed
            raise internal.exceptions.InvalidParameterError(u"{:s}.new({!r}, {!r}, ...{:s}) : Unable to add a new action due to the \"{:s}\" attribute being assigned a different type ({!s}) than what was expected ({!s}).".format('.'.join([__name__, cls.__name__]), name, scope, attributes_description, internal.utils.string.escape(key, '"'), value.__class__, expected))

        # If the matching dictionary is empty, then we issue a warning since
        # it's literally going to match everything which is probably unwanted.
        if not match:
            cls, attributes_description = self.__class__, ", {:s}".format(attributes_description) if attributes else ''
            logging.warning(u"{:s}.new({!r}, {!r}, ...{:s}) : Adding the \"{:s}\" action without matching any attributes ({!r}) will result in the action being activated everywhere and is not recommended.".format('.'.join([__name__, cls.__name__]), name, scope, attributes_description, internal.utils.string.escape(name, '"'), match))

        # That should be everything, so now we just need to gather the
        # parameters that will be used to instantiate the descriptor.

        # FIXME: might need to add some default flags to the descriptor.
        flags = [idaapi.ADF_OWN_HANDLER, idaapi.ADF_OT_PLUGIN]

        parameters = []
        for attribute in self.__action_attribute_order__:
            value = attributes.get(attribute, attribute_defaults[attribute])
            parameters.append(internal.utils.string.to(value) if isinstance(value, internal.types.string) else value)

        # Then we add it to our dictionary of descriptors ready to be attached.
        self.__descriptor_params__[name] = parameters
        self.__action_scope__[name] = scope.upper()
        self.__registration__[name] = match
        return name

    @classmethod
    def has(cls, name):
        '''Return whether an action with the given `name` has been registered into the disassembler.'''
        unmanaged = {internal.utils.string.of(action) for action in idaapi.get_registered_actions()}
        return name in unmanaged

    def update(self, name, **attributes):
        """Modify the attributes for the plugin action that is specified by `name`.

        This method can modify the attributes of the descriptor for either a
        managed or an unmanaged action. This allows changing the state for
        actions that are not owned by this class.

        The following attributes for a plugin action can be modified with this
        method:

            * `label` - The label for the action.
            * `shortcut` - The keyboard shortcut(s) associated with the action.
            * `tooltip` - The tooltip that the disassembler will display.
            * `icon` - An integer containing the icon to use for the action.
            * `state` - An integer containing the state of the action.
            * `checkable` - A boolean specifying that the action can be toggled.
            * `checked` - A boolean used for toggling the action.
            * `visiblity` - A boolean used for specifying action visibility.

        """
        attributes_description = internal.utils.string.kwargs(attributes)

        # first make sure that the plugin actions actually exists.
        if not self.has(name):
            cls, attributes_description = self.__class__, ", {:s}".format(attributes_description) if attributes else ''
            raise internal.exceptions.ItemNotFoundError(u"{:s}.update({!r}{:s}) : Unable to modify the attributes for action \"{:s}\" due to it not having been registered.".format('.'.join([__name__, cls.__name__]), name, attributes_description, internal.utils.string.escape(name, '"')))

        # now we need to go through and verify the attributes we were given.
        missing = {attribute for attribute in attributes if attribute not in self.__action_attribute_types__}
        if missing:
            cls, attributes_description = self.__class__, ", {:s}".format(attributes_description) if attributes else ''
            raise internal.exceptions.InvalidParameterError(u"{:s}.update({!r}{:s}) : Unable to modify the attributes for action \"{:s}\" due to some of the given attributes being unavailable ({:s}).".format('.'.join([__name__, cls.__name__]), name, attributes_description, internal.utils.string.escape(name, '"'), ', '.join(sorted(missing))))

        # before any type-checking is done on the attributes we were given, we
        # need to special-case the "shortcut" since it can be given as a string
        # or an unordered container of strings. If it's the latter, then we can
        # join them together with a "," to map multiple shortcuts to the action.
        if isinstance(attributes.get('shortcut'), internal.types.unordered):
            if not all(isinstance(item, internal.types.string) for item in attributes['shortcut']):
                cls, attributes_description = self.__class__, ", {:s}".format(attributes_description) if attributes else ''
                invalid = [item.__class__ for item in attributes['shortcut'] if not isinstance(item, internal.types.string)]
                expected_packed = self.__action_attribute_types__['shortcut']
                expected = next(iter(expected_packed)) if hasattr(expected_packed, '__iter__') else expected_packed
                raise internal.exceptions.InvalidParameterError(u"{:s}.update({!r}{:s}) : Unable to modify the attributes for action \"{:s}\" due to the \"{:s}\" attribute containing {:s} ({!s}) than what was expected ({!s}).".format('.'.join([__name__, cls.__name__]), name, attributes_description, internal.utils.string.escape(name, '"'), internal.utils.string.escape('shortcut', '"'), 'a different type' if len(invalid) == 1 else 'different types', ', '.join(map("{!s}".format, invalid)), expected))
            attributes['shortcut'] = ','.join(attributes['shortcut'])

        # then we can go ahead and verify their types are correct.
        invalid = []
        for attribute, value in attributes.items():
            expected = self.__action_attribute_types__[attribute]
            if not isinstance(value, expected):
                invalid.append((attribute, value.__class__, expected))
            continue

        if invalid:
            cls, attributes_description = self.__class__, ", {:s}".format(attributes_description) if attributes else ''
            raise internal.exceptions.InvalidTypeOrValueError(u"{:s}.update({!r}{:s}) : Unable to modify the attributes for action \"{:s}\" due to some of the given attributes ({:s}) having an unsupported type.".format('.'.join([__name__, cls.__name__]), name, attributes_description, internal.utils.string.escape(name, '"'), ', '.join(sorted(invalid))))

        # If all the attributes have the correct type, then start going through
        # them one-by-one and applying them to the specified plugin action. We
        # track some of the attributes in case one of the actions we manage is
        # being updated. This way we can keep the action descriptor in sync.
        modified = {}

        # Label
        ok, value = True, attributes.get('label')
        if 'label' in attributes:
            ok = idaapi.update_action_label(*map(internal.utils.string.to, [name, value]))
            ok and modified.setdefault('label', value)

        if not ok:
            cls, attributes_description = self.__class__, ", {:s}".format(attributes_description) if attributes else ''
            logging.warning(u"{:s}.update({!r}{:s}) : Unable to set the label for action \"{:s}\" to the string \"{:s}\".".format('.'.join([__name__, cls.__name__]), name, attributes_description, internal.utils.string.escape(name, '"'), internal.utils.string.escape(value, '"')))

        # Shortcut
        ok, value = True, attributes.get('shortcut')
        if 'shortcut' in attributes:
            ok = idaapi.update_action_shortcut(*map(internal.utils.string.to, [name, value]))
            ok and modified.setdefault('shortcut', value)

        if not ok:
            cls, attributes_description = self.__class__, ", {:s}".format(attributes_description) if attributes else ''
            logging.warning(u"{:s}.update({!r}{:s}) : Unable to set the shortcut for action \"{:s}\" to the string \"{:s}\".".format('.'.join([__name__, cls.__name__]), name, attributes_description, internal.utils.string.escape(name, '"'), internal.utils.string.escape(value, '"')))

        # Tooltip
        ok, value = True, attributes.get('tooltip')
        if 'tooltip' in attributes:
            ok = idaapi.update_action_tooltip(*map(internal.utils.string.to, [name, value]))
            ok and modified.setdefault('tooltip', value)

        if not ok:
            cls, attributes_description = self.__class__, ", {:s}".format(attributes_description) if attributes else ''
            logging.warning(u"{:s}.update({!r}{:s}) : Unable to set the tooltip for action \"{:s}\" to the string \"{:s}\".".format('.'.join([__name__, cls.__name__]), name, attributes_description, internal.utils.string.escape(name, '"'), internal.utils.string.escape(value, '"')))

        # Icon
        ok, value = True, attributes.get('icon')
        if 'icon' in attributes:
            ok = idaapi.update_action_icon(internal.utils.string.to(name), value)
            ok and modified.setdefault('icon', value)

        if not ok:
            cls, attributes_description = self.__class__, ", {:s}".format(attributes_description) if attributes else ''
            logging.warning(u"{:s}.update({!r}{:s}) : Unable to set the icon for action \"{:s}\" to the integer {:#x}.".format('.'.join([__name__, cls.__name__]), name, attributes_description, internal.utils.string.escape(name, '"'), value))

        # State
        ok, value = True, attributes.get('state')
        if 'state' in attributes:
            ok = idaapi.update_action_state(internal.utils.string.to(name), value)

        if not ok:
            cls, attributes_description = self.__class__, ", {:s}".format(attributes_description) if attributes else ''
            logging.warning(u"{:s}.update({!r}{:s}) : Unable to set the state for action \"{:s}\" to the integer {:#x}.".format('.'.join([__name__, cls.__name__]), name, attributes_description, internal.utils.string.escape(name, '"'), value))

        # Checkable
        ok, value = True, True if attributes.get('checkable') else False
        if 'checkable' in attributes:
            ok = idaapi.update_action_checkable(internal.utils.string.to(name), value)

        if not ok:
            cls, attributes_description = self.__class__, ", {:s}".format(attributes_description) if attributes else ''
            logging.warning(u"{:s}.update({!r}{:s}) : Unable to set the checkable attribute for action \"{:s}\" to {!s}.".format('.'.join([__name__, cls.__name__]), name, attributes_description, internal.utils.string.escape(name, '"'), value))

        # Checkable
        ok, value = True, True if attributes.get('checked') else False
        if 'checked' in attributes:
            ok = idaapi.update_action_checked(internal.utils.string.to(name), value)

        if not ok:
            cls, attributes_description = self.__class__, ", {:s}".format(attributes_description) if attributes else ''
            logging.warning(u"{:s}.update({!r}{:s}) : Unable to set the checked attribute for action \"{:s}\" to {!s}.".format('.'.join([__name__, cls.__name__]), name, attributes_description, internal.utils.string.escape(name, '"'), value))

        # Visibility
        ok, value = True, True if attributes.get('visibility') else False
        if 'visibility' in attributes:
            ok = idaapi.update_action_visibility(internal.utils.string.to(name), value)

        if not ok:
            cls, attributes_description = self.__class__, ", {:s}".format(attributes_description) if attributes else ''
            logging.warning(u"{:s}.update({!r}{:s}) : Unable to set the visibility for action \"{:s}\" to {!s}.".format('.'.join([__name__, cls.__name__]), name, attributes_description, internal.utils.string.escape(name, '"'), value))

        # If we aren't managing the action, then we're done and only need to
        # return the action name that was modified so that it can be reused.
        if name not in self.available:
            return name

        # Otherwise, we need to update the parameters for the instantiating the
        # action descriptor and update the attributes of the descriptor itself.
        original = self.__descriptor_params__[name]
        zipped = zip(self.__action_attribute_order__, original)
        iterable = (modified.get(attribute, item) for attribute, item in zipped)
        self.__descriptor_params__[name] = [item for item in iterable]

        descriptor = self.__descriptors__[name]
        iterable = (attribute for attribute in modified if attribute in self.__action_attribute_types__)
        [setattr(descriptor, attribute, modified[attribute]) for attribute in iterable]

        return name

    def add(self, name, activator, priority=0):
        '''Add the callable in `activator` to the queue for the action specified in `name` with the given `priority`.'''
        if name not in self.__descriptor_params__:
            cls, format = self.__class__, "{:+d}".format if isinstance(priority, internal.types.integer) else "{!r}".format
            raise TypeError(u"{:s}.add({!r}, {!s}, priority={:s}) : Unable to add a callable for activating the specified action (\"{:s}\") due to the action not having been registered.".format('.'.join([__name__, cls.__name__]), name, activator, format(priority), internal.utils.string.escape(name, '"')))

        if not self.attach(name):
            cls, format = self.__class__, "{:+d}".format if isinstance(priority, internal.types.integer) else "{!r}".format
            raise TypeError(u"{:s}.add({!r}, {!s}, priority={:s}) : Unable to attach the specified action (\"{:s}\").".format('.'.join([__name__, cls.__name__]), name, activator, format(priority), internal.utils.string.escape(name, '"')))
        return super(priorityaction, self).add(name, activator, priority)

class priorityhook_hexrays(priorityhook):
    """
    This is a helper class that allows one to dispatch a callable in response to
    an event produced by the disassembler or decompiler. Specifically, this
    class is intended to be used with the `idaapi.Hexrays_Hooks` class that is
    exposed by the python api. It is derived from the `priorityhook` helper
    class with the only difference being that no hooks are attached until the
    "Hex-Rays Decompiler" plugin has been loaded into the disassembler.

    The class accomplishes this by assigning the attribute "__hexrays_ready__"
    as a protected property that can be enabled to deny the attachment of a
    callable to an event. After this, the "plugin_loaded" and "plugin_unloaded"
    hooks are used to toggle this value. Upon detecting that the correct plugin
    has been loaded, all of the events that are associated with a callable are
    attached, and then the flag is set so that the instance works the same as
    the `priorityhook` base class. Once the associated plugin has been unloaded,
    this instance will detach all of the attached events and then clear the
    "__hexrays_ready__" attribute until the next time the plugin is loaded.
    """

    def __init__(self, klass, mapping={}, entries={}):
        '''Create an instance of the priority hook class that is only enabled when the decompiler plugin has been loaded.'''
        super(priorityhook_hexrays, self).__init__(klass, mapping=mapping, entries=entries)

        # Set the current state for hexrays to non-ready so that nothing gets
        # attached until the plugin we're waiting for gets loaded.
        self.__hexrays_ready__ = False

    def add(self, name, callable, priority=0):
        '''Add the `callable` to the queue for the specified `name` with the given `priority`.'''
        cls = self.__class__

        # If the decompiler plugin is not ready, then simulate an attachment.
        if not self.__hexrays_ready__:
            return super(priorityhook, self).add(name, callable, priority)

        # Otherwise, since the decompiler has been loaded we can just attach it.
        if not self.attach(name):
            raise internal.exceptions.DisassemblerError(u"{:s}.add({:#x}, {!s}, {:+d}) : Unable to attach to the {:s} event.".format('.'.join([__name__, cls.__name__]), name, callable, priority, self.__formatter__(name)))

        # Add the callable to the queue for the given target name.
        return super(priorityhook_hexrays, self).add(name, callable, priority)

    def __repr__(self):
        message = 'attached' if getattr(self, '__hexrays_ready__', False) else 'being monitored (decompiler not loaded)'
        if len(self):
            res, items = "Events currently {:s}:".format(message), super(priorityhook_hexrays, self).__repr__().split('\n')
            return '\n'.join([res] + items[1:])
        return "Events currently {:s}: {:s}".format(message, 'No events are being monitored.')

    # Callbacks to enable the attachment of hooks once the decompiler has been loaded.
    __plugin_required = {'Hex-Rays Decompiler'}
    def __plugin_loaded__(self, plugin_info):
        cls, plugin_name = self.__class__, internal.utils.string.of(plugin_info.name)
        if plugin_name not in self.__plugin_required:
            return

        import ida_hexrays as module

        # Initialize the hexrays plugin so that we know that it is available.
        logging.debug(u"{:s} : Initializing the Hex-Rays plugin with `{:s}` due to receiving a plugin loaded event for \"{:s}\".".format('.'.join([__name__, cls.__name__]), internal.utils.pycompat.fullname(module.init_hexrays_plugin), internal.utils.string.escape(plugin_name, '"')))
        if not module.init_hexrays_plugin():
            cls = self.__class__
            raise internal.exceptions.DisassemblerError(u"{:s} : Failure while trying initialize the Hex-Rays plugin with `{:s}`.".format('.'.join([__name__, cls.__name__]), internal.utils.pycompat.fullname(module.init_hexrays_plugin)))

        # Toggle our boolean that we use for keeping track of when the
        # decompiler plugin has been loaded or not.
        self.__hexrays_ready__ = True

        # Now we need to go through all of the events that were hooked by the
        # user and attach each of them so that they will get dispatched to by
        # the disassembler and decompiler.
        logging.debug(u"{:s} : Attaching {:d} event{:s} for the Hex-Rays plugin due to receiving a plugin loaded event for \"{:s}\".".format('.'.join([__name__, cls.__name__]), len(self), '' if len(self) == 1 else 's', internal.utils.string.escape(plugin_name, '"')))
        for name in sorted(self):
            if not self.attach(name):
                logging.warning(u"{:s} : Unable to attach the {:s} event during the loading process of the Hex-Rays plugin.".format('.'.join([__name__, cls.__name__]), self.__formatter__(name)))
            continue
        return

    def __plugin_unloading__(self, plugin_info):
        cls, plugin_name = self.__class__, internal.utils.string.of(plugin_info.name)
        if plugin_name not in self.__plugin_required:
            return

        # Go through and detach everything that is currently hooked.
        logging.debug(u"{:s} : Detaching {:d} event{:s} for the Hex-Rays plugin due to receiving a plugin unloaded event for \"{:s}\".".format('.'.join([__name__, cls.__name__]), len(self), '' if len(self) == 1 else 's', internal.utils.string.escape(plugin_name, '"')))
        for event in self:
            if not self.detach(event):
                logging.warning(u"{:s} : Unable to detach the {:s} event during the unloading process of the Hex-Rays plugin.".format('.'.join([__name__, cls.__name__]), self.__formatter__(event)))
            continue

        # Now we can modify our state that disables our instance.
        self.__hexrays_ready__ = False

class database(object):
    """
    This namespace provides tools that can be used to get specific
    information about the current database configuration. Most of
    the information about the database is being extracted from the
    `idainfo` structure which is initialized upon database creation.
    """

    # cache the initial idainfo structure, but it should get updated by one of the hooks.
    __idainfo__ = idaapi.get_inf_structure()

    @classmethod
    def __init_info_structure__(cls, idp_modname):
        idainfo = idaapi.get_inf_structure()
        if idainfo:
            logging.debug(u"{:s}.__init_info_structure__({!s}) : Successfully fetched and cached information structure for database.".format('.'.join([__name__, cls.__name__]), internal.utils.string.escape(idp_modname, '"')))

            # Display summary of the database and what it's used for.
            bits = "{:d}-bit".format(64 if idainfo.is_64bit() else 32 if idainfo.is_32bit() else 16)
            format = 'library' if idainfo.lflags & idaapi.LFLG_IS_DLL else 'binary'

            if idaapi.__version__ < 7.0:
                byteorder = "{:s}-endian".format('big' if idaapi.cvar.inf.mf else 'little')
            else:
                byteorder = "{:s}-endian".format('big' if idainfo.lflags & idaapi.LFLG_MSF else 'little')

            if idaapi.__version__ >= 7.0:
                mode = ' kernelspace' if idainfo.lflags & idaapi.LFLG_KERNMODE else ' userspace'
            else:
                mode = ''
            logging.warning(u"Initialized {tag!s} database v{version:d} for {bits:s} {byteorder:s}{mode:s} {format:s}.".format('.'.join([idainfo.__class__.__module__, idainfo.__class__.__name__]), tag=idainfo.tag, bits=bits, byteorder=byteorder, mode=mode, format=format, version=idainfo.version))

        else:
            logging.fatal(u"{:s}.__init_info_structure__({!s}) : Unknown error while trying to get information structure for database.".format('.'.join([__name__, cls.__name__]), internal.utils.string.escape(idp_modname, '"')))
        cls.__idainfo__ = idainfo

    @classmethod
    def __nw_init_info_structure__(cls, nw_code, is_old_database):
        logging.debug(u"{:s}.__nw_init_info_structure__({!s}) : Received notification to initialize information structure for database.".format('.'.join([__name__, cls.__name__]), ', '.join(map("{!r}".format, [nw_code, is_old_database]))))
        idp_modname = idaapi.get_idp_name()
        return cls.__init_info_structure__(idp_modname)

    @classmethod
    def version(cls):
        '''Return the version of the database.'''
        if idaapi.__version__ < 7.2:
            return cls.__idainfo__.version
        return idaapi.inf_get_version()

    @classmethod
    def byteorder(cls):
        '''Return a string representing the byte-order used by integers in the database.'''
        if idaapi.__version__ < 7.0:
            res = idaapi.cvar.inf.mf
            return 'big' if res else 'little'
        return 'big' if cls.flags(idaapi.LFLG_MSF) else 'little'

    @classmethod
    def bits(cls):
        '''Return number of bits for the processor used by the current database.'''
        result = cls.flags(idaapi.LFLG_PC_FLAT | idaapi.LFLG_64BIT)
        if result & idaapi.LFLG_64BIT:
            return 64
        elif result & idaapi.LFLG_PC_FLAT:
            return 32
        return 32 if result & idaapi.LFLG_FLAT_OFF32 else 16

    @classmethod
    def flags(cls, *mask):
        '''Return the value of the ``idainfo.lflags`` field from the database with the specified `mask`.'''
        lflags = cls.__idainfo__.lflags if idaapi.__version__ < 7.2 else idaapi.inf_get_lflags()
        return operator.and_(lflags, *mask) if mask else lflags

    @classmethod
    def setflags(cls, mask, value):
        '''Set the ``idainfo.lflags`` with the provided `mask` from the database to the specified `value`.'''
        if idaapi.__version__ < 7.2:
            ok, cls.__idainfo__.lflags = True, (result & ~mask) | (value & mask)

        # Newer versions of IDA use the idaapi.inf_set_lflags() function.
        else:
            ok = idaapi.inf_set_lflags((result & ~mask) | (value & mask))
        return True if ok else False

    @classmethod
    def filename(cls):
        '''Return the filename that the currently open database was built from.'''
        res = idaapi.get_root_filename()
        return internal.utils.string.of(res)

    @classmethod
    def idb(cls):
        '''Return the full path to the currently open database.'''
        res = idaapi.cvar.database_idb if idaapi.__version__ < 7.0 else idaapi.get_path(idaapi.PATH_TYPE_IDB)
        string = internal.utils.string.of(res)
        return string.replace(os.sep, '/')

    @classmethod
    def path(cls):
        '''Return the absolute path to the directory containing the currently open database.'''
        res = idaapi.cvar.database_idb if idaapi.__version__ < 7.0 else idaapi.get_path(idaapi.PATH_TYPE_IDB)
        string = internal.utils.string.of(res)
        path, _ = os.path.split(string.replace(os.sep, '/'))
        return path

    @classmethod
    def imagebase(cls):
        '''Return the baseaddress of the image that has been opened.'''
        return idaapi.get_imagebase()

    @classmethod
    def readonly(cls):
        '''Return whether the current database is read-only or not.'''
        if idaapi.__version__ < 7.0:
            raise internal.exceptions.UnsupportedVersion(u"{:s}.readonly() : This function is only supported on versions of IDA 7.0 and newer.".format('.'.join([__name__, cls.__name__])))
        elif idaapi.__version__ < 7.2:
            ok = cls.__idainfo__.readonly_idb()
        else:
            ok = idaapi.inf_readonly_idb()
        return True if ok else False

    @classmethod
    def filetype(cls):
        '''Return the file type identified by the loader when creating the database.'''
        if idaapi.__version__ < 7.2:
            return cls.__idainfo__.filetype
        return idaapi.inf_get_filetype()

    @classmethod
    def setfiletype(cls, filetype_t):
        '''Set the file type identified by the loader to the specified `filetype_t`.'''
        if idaapi.__version__ < 7.2:
            ok, cls.__idainfo__.filetype = True, filetype_t

        # Newer versions of IDA use the idaapi.inf_get_filetype() and idaapi.inf_set_filetype() functions.
        else:
            ok = idaapi.inf_set_filetype(filetype_t)
        return True if ok else False

    @classmethod
    def ostype(cls):
        '''Return the operating system type identified by the loader when creating the database.'''
        # FIXME: this is a bitflag that should be documented in libfuncs.hpp
        #        which unfortunately is not included anywhere in the sdk.
        if idaapi.__version__ < 7.2:
            return cls.__idainfo__.ostype
        return idaapi.inf_get_ostype()

    @classmethod
    def setostype(cls, ostype_t):
        '''Set the operating system type for the database to the specified `ostype_t`.'''
        if idaapi.__version__ < 7.2:
            ok, cls.__idainfo__.ostype = True, ostype_t

        # Newer versions of IDA use the idaapi.inf_get_filetype() and idaapi.inf_set_filetype() functions.
        else:
            ok = idaapi.inf_set_ostype(ostype_t)
        return True if ok else False

    @classmethod
    def apptype(cls):
        '''Return the application type identified by the loader when creating the database.'''
        # FIXME: this is a bitflag that should be documented in libfuncs.hpp
        #        which unfortunately is not included anywhere in the sdk.
        if idaapi.__version__ < 7.2:
            return cls.__idainfo__.apptype
        return idaapi.inf_get_apptype()

    @classmethod
    def setapptype(cls, apptype_t):
        '''Set the application type for the current database to the specified `apptype_t`.'''
        if idaapi.__version__ < 7.2:
            ok, cls.__idainfo__.apptype = True, apptype_t

        # Newer versions of IDA use the idaapi.inf_get_filetype() and idaapi.inf_set_filetype() functions.
        else:
            ok = idaapi.inf_set_apptype(apptype_t)
        return True if ok else False

    @classmethod
    def changecount(cls):
        '''Return the number of changes within the current database.'''
        if idaapi.__version__ < 7.0:
            return None
        elif idaapi.__version__ < 7.2:
            return cls.__idainfo__.database_change_count
        return idaapi.inf_get_database_change_count()

    @classmethod
    def processor(cls):
        '''Return the name of the processor used by the currently open database.'''
        if idaapi.__version__ < 7.0:
            return None
        elif hasattr(cls.__idainfo__, 'procname'):
            result = cls.__idainfo__.procname
        elif hasattr(cls.__idainfo__, 'procName'):
            result = cls.__idainfo__.procName
        else:
            result = idaapi.inf_get_procname()
        return internal.utils.string.of(result)

    @classmethod
    def compiler(cls):
        '''Return the compiler that was configured for the current database.'''
        if idaapi.__version__ < 7.2:
            return cls.__idainfo__.cc

        # Newer versions of IDA use the idaapi.inf_get_cc() function.
        cc = idaapi.compiler_info_t()
        return cc if idaapi.inf_get_cc(cc) else None

    @classmethod
    def entrypoint(cls):
        '''Return the first entry point for the database.'''
        if idaapi.__version__ < 7.2:
            return cls.__idainfo__.start_ea
        return idaapi.inf_get_start_ea()

    @classmethod
    def margin(cls):
        '''Return the current margin position for the current database.'''
        if idaapi.__version__ < 7.2:
            return cls.__idainfo__.margin
        return idaapi.inf_get_margin()

    @classmethod
    def strtype(cls):
        '''Return the default string type configured for the current database.'''
        if idaapi.__version__ < 7.2:
            return cls.__idainfo__.strtype
        return idaapi.inf_get_strtype()

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

    @classmethod
    def flags(cls, ea, *mask):
        '''Return the flags at the address `ea` masked with `mask`.'''
        getflagsex = idaapi.get_flags_ex if hasattr(idaapi, 'get_flags_ex') else (lambda ea, _: idaapi.get_full_flags(ea)) if hasattr(idaapi, 'get_full_flags') else (lambda ea, _: idaapi.getFlags(ea))
        ea, flags = int(ea), getflagsex(int(ea), getattr(idaapi, 'GFE_VALUE', 0))
        if not mask:
            return idaapi.as_uint32(flags)
        elif len(mask) == 1:
            return getflagsex(ea, getattr(idaapi, 'GFE_VALUE', 0)) & idaapi.as_uint32(int(*mask))
        elif len(mask) != 2:
            raise internal.exceptions.InvalidParameterError(u"{:s}.flags({:#x}, {:s}) : An unsupported number of parameters ({:d}) were provided for the given function.".format('.'.join([__name__, cls.__name__]), ea, ", {:s}".format(', '.join(map("{!r}".format, mask))), len(mask)))
        elif hasattr(idaapi, 'setFlags'):
            [mask, value] = mask
            idaapi.setFlags(ea, (flags & ~mask) | value)
            return res & mask
        [mask, value] = mask
        raise internal.exceptions.UnsupportedVersion(u"{:s}.flags({:#x}, {:#x}, {:d}) : Modifying the flags for an address has since been deprecated by the disassembler.".format('.'.join([__name__, cls.__name__]), ea, mask, value))

    @classmethod
    def references(cls, ea):
        '''Return each address within the item at address `ea` that has a reference to it.'''
        getflagsex = idaapi.get_flags_ex if hasattr(idaapi, 'get_flags_ex') else (lambda ea, _: idaapi.get_full_flags(ea)) if hasattr(idaapi, 'get_full_flags') else (lambda ea, _: idaapi.getFlags(ea))
        return [ea for ea in builtins.range(ea, ea + idaapi.get_item_size(ea)) if getflagsex(ea, 0) & idaapi.FF_REF]

    @classmethod
    def has(cls, ea):
        '''Return whether the address `ea` is contained within the database and accessible.'''
        Fis_mapped = getattr(idaapi, 'isEnabled' if idaapi.__version__ < 7.0 else 'is_mapped', None)
        if Fis_mapped:
            return Fis_mapped(int(ea))
        start, stop = cls.bounds()
        return start <= int(ea) < stop

    @classmethod
    def bounds(cls):
        '''Return the smallest and largest address within the database as a tuple.'''
        if idaapi.__version__ < 7.2:
            info = idaapi.get_inf_structure()
            min, max = info.minEA, info.maxEA
        else:
            min, max = idaapi.inf_get_min_ea(), idaapi.inf_get_max_ea()
        return bounds_t(min, max)

    # XXX: The following protected functions are marked as such due to them
    #      them having the ability to work on a single or pair of addresses.
    #      These are specifically used to adjust inputs so that you can select
    #      a pair that cuddle an item in the database, are inclusive to the
    #      address pair, or exclude one of the addresses specified in the
    #      pair.
    #
    #      There are also variations for both the head and tail of an address
    #      that can be specified to complain about an inexact pair before
    #      adjustment. The intention is so that you can specify pairs that
    #      are out-of-bounds or unaligned for some api, but still get both of
    #      them corrected to a head, tail, inclusive cuddle, or the exclusive
    #      cuddle for a range, a segment, or even the entire database.

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
    def __within__(cls, ea):
        '''Return whether the address `ea` is within the bounds of the database.'''
        start, stop = cls.bounds()
        return start <= ea < stop
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

    @classmethod
    def clamp_forward(cls, ea):
        '''Return the maximum available address in the database if the address in `ea` comes after it.'''
        left, right = cls.bounds()
        maximum = idaapi.prev_not_tail(right)
        return maximum if ea >= maximum else ea

    @classmethod
    def clamp_backward(cls, ea):
        '''Return the minimum available address in the database if the address in `ea` comes before it.'''
        left, right = cls.bounds()
        minimum = idaapi.next_not_tail(left)
        return minimum if ea <= minimum else ea

    # Now we can return back to our regularly scheduled program...

    @classmethod
    def refinfo(cls, ea, *opnum):
        '''This returns the ``idaapi.refinfo_t`` for the operand `opnum` belonging to the address given in `ea`.'''
        ri, OPND_ALL = idaapi.refinfo_t(), getattr(idaapi, 'OPND_ALL', 0xf)
        [opnum] = opnum if opnum else [OPND_ALL]
        ok = idaapi.get_refinfo(int(ea), opnum, ri) if idaapi.__version__ < 7.0 else idaapi.get_refinfo(ri, int(ea), opnum)
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

    @classmethod
    def walk_backward(cls, ea, step):
        '''Start at the address `ea` walking backwards through each address return by `step`.'''
        start = ea
        try:
            ea, next = step(start), ea + 1
        except internal.exceptions.OutOfBoundsError:
            ea, next = None, ea

        # After our first step, continue in a loop yielding each taken step. We don't
        # need to adjust anything because find_prev skips over the current address.
        try:
            while ea not in {idaapi.BADADDR, None} and ea < next:
                next = ea
                yield ea
                ea = step(next)

            logging.info(u"{:s}.walk_backward({:#x}, {!s}) : Walking backwards from address {:#x} terminated at {:#x}.".format('.'.join([__name__, cls.__name__]), start, internal.utils.pycompat.fullname(step), start, next))

        except internal.exceptions.OutOfBoundsError:
            logging.info(u"{:s}.walk_backward({:#x}, {!s}) : Walking backwards from address {:#x} terminated at {:#x} due to the address being out-of-bounds.".format('.'.join([__name__, cls.__name__]), start, internal.utils.pycompat.fullname(step), start, next))

    @classmethod
    def walk_forward(cls, ea, step):
        '''Start at the address `ea` walking forwards through each address return by `step`.'''
        start = ea
        try:
            ea, next = step(start), ea - 1
        except internal.exceptions.OutOfBoundsError:
            ea, next = None, ea

        # After our first step, continue in a loop yielding each taken step while
        # adjusting the following step by +1 to avoid the potential infinite loop.
        try:
            while ea not in {idaapi.BADADDR, None} and ea > next:
                next = ea
                yield ea
                ea = step(next + 1)

            logging.info(u"{:s}.walk_forward({:#x}, {!s}) : Walking forwards from address {:#x} terminated at {:#x}.".format('.'.join([__name__, cls.__name__]), start, internal.utils.pycompat.fullname(step), start, next))

        except internal.exceptions.OutOfBoundsError:
            logging.info(u"{:s}.walk_forward({:#x}, {!s}) : Walking forwards from address {:#x} terminated at {:#x} due to the address being out-of-bounds.".format('.'.join([__name__, cls.__name__]), start, internal.utils.pycompat.fullname(step), start, next))
        return

    @classmethod
    def iterate(cls, ea, step):
        '''Start at the address `ea` yielding each address returned by the callable `step`.'''
        start = next = ea
        try:
            ea = step(next)
        except internal.exceptions.OutOfBoundsError:
            ea = next

        # Continue in a loop yielding each value returned from our callable. If
        # the returned address is bad or results in a cycle, then we can bail.
        try:
            while ea not in {next, idaapi.BADADDR, None}:
                next = ea
                yield ea
                ea = step(next)

            logging.info(u"{:s}.iterate({:#x}, {!s}) : Iteration starting from address {:#x} terminated at {:#x}.".format('.'.join([__name__, cls.__name__]), start, internal.utils.pycompat.fullname(step), start, next))

        except internal.exceptions.OutOfBoundsError:
            logging.info(u"{:s}.iterate({:#x}, {!s}) : Iteration starting from address {:#x} terminated at {:#x} due to the address being out-of-bounds.".format('.'.join([__name__, cls.__name__]), start, internal.utils.pycompat.fullname(step), start, next))
        return

    @classmethod
    def offset(cls, ea):
        '''Return the address `ea` translated to an offset relative to the base address of the database.'''
        return ea - database.imagebase()

    @classmethod
    def color(cls, ea, *rgb):
        '''Get the color (RGB) for the item at address `ea` or set it to the color given by `rgb`.'''
        original, DEFCOLOR = idaapi.get_item_color(int(ea)), 0xffffffff

        # Set the color for the item at address `ea` to `rgb`.
        if rgb:
            r, b = (operator.and_(0xff * shift, *rgb) // shift for shift in [0x010000, 0x000001])
            idaapi.set_item_color(int(ea), DEFCOLOR if operator.contains({None, DEFCOLOR}, *rgb) else sum([b * 0x010000, operator.and_(0x00ff00, *rgb), r * 0x000001]))

        # Return the original color (BGR) with its order set to to RGB.
        b, r = (operator.and_(original, 0xff * shift) // shift for shift in [0x010000, 0x000001])
        return original if original == DEFCOLOR else sum([0x010000 * r, 0x00ff00 & original, 0x000001 * b])

    @classmethod
    def has_typeinfo(cls, ea):
        '''Return if the address at `ea` has any type information associated with it.'''
        ok = cls.typeinfo(int(ea)) is not None

        # If we couldn't find any type information, then we need to check if
        # the name is mangled since a mangled name can be used to guess for it.
        if not ok and not (function.has(int(ea)) and range.start(function.by_address(int(ea))) == ea):
            realname, guessed = name.get(int(ea)), idaapi.guess_tinfo2(ea, idaapi.tinfo_t()) if idaapi.__version__ < 7.0 else idaapi.guess_tinfo(idaapi.tinfo_t(), ea)
            return internal.declaration.demangle(realname) != realname and guessed != idaapi.GUESS_FUNC_FAILED
        return ok

    @classmethod
    def typeinfo(cls, ea):
        '''Return the type information for the address `ea` as an ``idaapi.tinfo_t``.'''
        ea, get_tinfo = int(ea), (lambda ti, ea: idaapi.get_tinfo2(ea, ti)) if idaapi.__version__ < 7.0 else idaapi.get_tinfo

        # First try and get the actual typeinfo for the given address. If it
        # actually worked, then we can just return it as-is.
        ti = idaapi.tinfo_t()
        if get_tinfo(ti, ea):
            return tinfo.concretize(ti)

        # Otherwise we'll go ahead and guess the typeinfo for the same address.
        res = idaapi.guess_tinfo2(ea, ti) if idaapi.__version__ < 7.0 else idaapi.guess_tinfo(ti, ea)

        # If we failed, then we'll try and hack around it using idaapi.print_type
        # and parsing the result. If we don't succeed, then we assume no type.
        if res != idaapi.GUESS_FUNC_OK:
            fl = idaapi.PRTYPE_1LINE
            info_s = idaapi.print_type(ea, fl)
            ti = None if info_s is None else tinfo.parse(None, info_s, idaapi.PT_SIL)
            if info_s is not None and ti is None:
                raise internal.exceptions.InvalidTypeOrValueError(u"{:s}.typeinfo({:#x}) : Unable to parse the type declaration (\"{:s}\") returned from the requested address ({:#x}).".format('.'.join([__name__, cls.__name__]), ea, internal.utils.string.escape(info_s, '"'), ea))
            return tinfo.concretize(ti)
        return tinfo.concretize(ti)

    @classmethod
    def apply_typeinfo(cls, ea, info, *flags):
        '''Apply the given type information in `info` to the address `ea` with the given `flags`.'''
        ea = int(ea)

        # If `info` is None, then we're only being asked to remove the type information.
        if info is None and any(hasattr(idaapi, attribute) for attribute in ['del_tinfo', 'del_tinfo2']):
            del_tinfo = idaapi.del_tinfo2 if idaapi.__version__ < 7.0 else idaapi.del_tinfo
            void = del_tinfo(ea)
            return True

        # If `info` is None, but we don't have an API then we don't have a real way to remove
        # type information. Still, we can remove the NSUP_TYPEINFO(3000) and clear its aflags.
        elif info is None:
            supvals = [idaapi.NSUP_TYPEINFO, idaapi.NSUP_TYPEINFO + 1]
            aflags = [idaapi.AFL_TI, idaapi.AFL_USERTI, getattr(idaapi, 'AFL_HR_GUESSED_FUNC', 0x40000000), getattr(idaapi, 'AFL_HR_GUESSED_DATA', 0x80000000)]

            # Save the original type, and zero out everything. This should pretty much get it done...
            discard = node.aflags(ea, functools.reduce(operator.or_, aflags), 0)
            [ internal.netnode.sup.remove(ea, val) for val in supvals ]
            return True

        # Now we need to figure out what flags to use when applying the type. If
        # the caller didn't provide any flags, we try to preserve them with the
        # intention that type changes are always guesses unless they're explicit.
        guessed = node.aflags(ea, idaapi.AFL_TYPE_GUESSED if hasattr(idaapi, 'AFL_TYPE_GUESSED') else idaapi.AFL_USERTI)
        definitive = True if guessed == idaapi.AFL_USERTI or guessed & getattr(idaapi, 'AFL_HR_DETERMINED', 0xC0000000) else False
        [tflags] = itertools.chain(flags if flags else [idaapi.TINFO_DEFINITE if definitive else idaapi.TINFO_GUESSED])

        # If the aflags already claim that this is a user-specified type, but we
        # were asked to apply it non-definitively, then we need to clear the aflag.
        if flags and tflags == idaapi.TINFO_GUESSED and definitive:
            node.aflags(ea, idaapi.AFL_USERTI, 0)

        # Now everything is set to use idaapi and apply our tinfo_t to the address.
        ok = idaapi.apply_tinfo(ea, info, tflags)

        # If the caller gave us explicit flags to apply as TINFO_GUESSED, then
        # we need to clear the aflags to force the applied type as being guessed.
        if ok and flags and tflags & idaapi.TINFO_GUESSED:
            node.aflags(ea, idaapi.AFL_USERTI, 0)
        return ok

    @classmethod
    def read(cls, ea, size):
        '''Read `size` number of bytes from the database at address `ea` and return them.'''
        if idaapi.__version__ < 7.0:
            return idaapi.get_many_bytes(int(ea), max(0, size)) or b''
        return idaapi.get_bytes(int(ea), max(0, size)) or b''

    @classmethod
    def items(cls, start, stop):
        '''Iterate through all of the items from the address `start` until right before the address `stop`.'''
        left, right = cls.within(*sorted(map(int, [start, stop])))
        ea, step, Fwhile = (left, idaapi.next_not_tail, functools.partial(operator.gt, right)) if start <= stop else (right, idaapi.prev_not_tail, functools.partial(operator.le, left))
        iterable = itertools.takewhile(Fwhile, cls.iterate(ea, step))
        return itertools.chain([ea], iterable)

    @classmethod
    def structure(cls, ea):
        '''Return the union or structure identifier for the item at address `ea`.'''
        is_struct = idaapi.is_struct if hasattr(idaapi, 'is_struct') else internal.utils.fcompose(functools.partial(operator.and_, idaapi.DT_TYPE), functools.partial(operator.eq, idaapi.FF_STRUCT if hasattr(idaapi, 'FF_STRUCT') else idaapi.FF_STRU))

        # First check if there's a structure/union at the specified address.
        ea, info, flags = int(ea), idaapi.opinfo_t(), cls.flags(int(ea))
        if not is_struct(flags):
            return idaapi.BADNODE

        # Grab the operand information (really operand 0), and return the type id.
        ok = idaapi.get_opinfo(ea, idaapi.OPND_ALL, flags, info) if idaapi.__version__ < 7.0 else idaapi.get_opinfo(info, ea, idaapi.OPND_ALL, flags)
        if not ok:
            return idaapi.BADNODE
        return info.tid

    @classmethod
    def enumeration(cls, ea, *opnum):
        '''Return the enumeration identifier and serial for the enumeration at address `ea`.'''
        ea, info, flags = int(ea), idaapi.opinfo_t(), cls.flags(int(ea))

        # Verify that there's an enumeration at the suggested address.
        has_enum = idaapi.is_enum(flags, *(opnum if opnum else [idaapi.OPND_ALL])) if hasattr(idaapi, 'is_enum') else bool(flags & operator.getitem([idaapi.FF_0ENUM, idaapi.FF_1ENUM], *opnum) if opnum else idaapi.enum_flag() if hasattr(idaapi, 'enum_flag') else idaapi.enumflag())
        if not has_enum:
            return

        # Use the operand information to extract the identifier and serial for the enumeration member.
        ok = idaapi.get_opinfo(ea, idaapi.OPND_ALL, flags, info) if idaapi.__version__ < 7.0 else idaapi.get_opinfo(info, ea, idaapi.OPND_ALL, flags)
        if not ok:
            return
        return info.ec.tid, info.ec.serial

    @classmethod
    def string(cls, ea):
        '''Return the unpacked string type for the string at the address `ea`.'''
        is_string = idaapi.is_strlit if hasattr(idaapi, 'is_strlit') else internal.utils.fcompose(functools.partial(operator.and_, idaapi.DT_TYPE), functools.partial(operator.eq, idaapi.FF_STRLIT if hasattr(idaapi, 'FF_STRLIT') else idaapi.FF_ASCI))

        # Check that the suggested address has a string applied to it.
        ea, info, flags = int(ea), idaapi.opinfo_t(), cls.flags(int(ea))
        if not is_string(flags):
            return

        # Unpack the string type from the operand information for the address.
        ok = idaapi.get_opinfo(ea, idaapi.OPND_ALL, flags, info) if idaapi.__version__ < 7.0 else idaapi.get_opinfo(info, ea, idaapi.OPND_ALL, flags)
        if ok:
            return string.unpack(info.strtype)
        return

    @classmethod
    def custom(cls, ea):
        '''Return the custom data type id and a list of its formats for the item at address `ea`.'''
        is_custom = idaapi.is_custom if hasattr(idaapi, 'is_custom') else internal.utils.fcompose(functools.partial(operator.and_, idaapi.DT_TYPE), functools.partial(operator.eq, idaapi.FF_CUSTOM))

        # Check if there's a custom data type applied to the address.
        ea, info, flags = int(ea), idaapi.opinfo_t(), cls.flags(int(ea))
        if not is_custom(flags):
            return

        # Try to grab the operand information from the suggested address.
        ok = idaapi.get_opinfo(ea, idaapi.OPND_ALL, flags, info) if idaapi.__version__ < 7.0 else idaapi.get_opinfo(info, ea, idaapi.OPND_ALL, flags)
        if not ok:
            return

        # Extract the custom data type and unpack all of its format identifiers.
        cd = oi.cd
        if hasattr(cd.fids, 'bytes'):
            paired = zip(*[iter(bytearray(cd.fids.bytes))] * 2)
            fids = [ 0x100 * hi + lo for lo, hi in paired ]

        # Cast all the formats from the data type into an array and return it.
        else:
            address, parray_t = int(cd.fids), ctypes.POINTER(ctypes.c_int16 * idaapi.UA_MAXOP)
            fids = [integer for integer in ctypes.cast(ctypes.c_void_p(address), parray_t).contents]
        return cd.dtid, fids

    # XXX: the following function should really have been deprecated some time ago...
    #      unfortunately, it is still here because of the <M-up> and <M-down> hotkeys
    #      in the disassembler. Once we start precalculating things for code flow,
    #      then we can do something different when inside a function. however, if we
    #      are outside a function without references, this is the best that we can do.

    @classmethod
    def scan_register(cls, start, stop, registers, predicate=None, *count, **modifiers):
        '''Scan for the specified `registers` from the address `start` through `stop` while `predicate` returns true.'''
        start, stop, utils, registers = int(start), int(stop), internal.utils, [register for register in registers]
        Fwhile = functools.partial(operator.gt if start <= stop else operator.le, stop)

        # gather our predicates that we will use for the actual matching.
        Fmatches_register = utils.fcompose(regmatch(*registers, **modifiers), bool)
        Fmatches = utils.fcompose(utils.fthrough(Fmatches_register, predicate), all) if callable(predicate) else Fmatches_register

        # figure out which functions to use for moving in the desired
        # direction, and grab the result number out of the parameter.
        Fnext = idaapi.next_not_tail if start <= stop else idaapi.prev_not_tail
        [count] = count if count else [1]

        # build our generators that we will use for scanning the range of addresses.
        iterable_with_flags = ((ea, cls.flags(ea, idaapi.MS_CLS)) for ea in cls.iterate(start, Fnext) if Fwhile(ea))
        iterable = (ea for ea, flags in iterable_with_flags if flags == idaapi.FF_CODE and Fmatches(ea))

        # now grab all matching addresses up to the specified count. if we didn't
        # retrieve enough items, then we seeked past the sentinel value and bail.
        result = [ea for index, ea in zip(builtins.range(count), iterable)]
        if count and len(result) < count:
            register_description = u', '.join("{!s}".format(register) for register in registers)
            raise internal.exceptions.RegisterNotFoundError(u"{:s}.scan_register({:#x}, {:#x}, {:s}, {!s}, {:d}{:s}) : Unable to find address{:s} matching the requested register{:s} within the range {:#x}..{:#x}. Stopped at last matching address ({:#x}).".format('.'.join([__name__, cls.__name__]), start, stop, "[{:s}]".format(register_description), utils.pycompat.fullname(predicate) if callable(predicate) else predicate, count, ", {:s}".format(utils.string.kwargs(modifiers)) if modifiers else '', " #{:d}".format(count) if count else '', '' if len(registers) == 1 else 's', start, stop, result[-1] if result else start))
        return result[-1] if result else start

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

    @classmethod
    def vector(cls, iterable):
        '''Return the boundaries specified in `iterable` as a vector of ranges.'''
        item_t, vector_t = (idaapi.area_t, idaapi.areavec_t) if idaapi.__version__ < 7.0 else (idaapi.range_t, idaapi.rangevec_t)
        vector = vector_t()
        for bounds in iterable:
            if isinstance(bounds, item_t):
                start, stop = cls.unpack(bounds)
            elif hasattr(bounds, 'bounds'):
                start, stop = bounds.bounds
            elif isinstance(bounds, (bounds_t, tuple)):
                start, stop = bounds
            else:
                start, stop = (lambda integer: (integer, integer + 1))(int(bounds))
            range = item_t(start, stop)
            vector.push_back(range)
        return vector

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

        # XXX: This is pretty much deprecated and shouldn't ever be used.

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
        path, moffset, realoffset = [], 0, 0
        for realoffset, packed in internal.structure.members.at(st.ptr, offset):
            mowner, mindex, mptr = packed
            path.append((mowner, mptr))
            moffset = 0 if mptr.flag & idaapi.MF_UNIMEM else mptr.soff
        delta = offset - (realoffset + moffset)
        return delta, path

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

    @classmethod
    def aflags(cls, ea, *mask):
        '''Apply or return the additional flags for the item at address `ea` using the given `mask` and another integer as the value..'''
        NALT_AFLAGS = getattr(idaapi, 'NALT_AFLAGS', 8)
        result = idaapi.get_aflags(int(ea)) if hasattr(idaapi, 'get_aflags') else internal.netnode.alt.get(idaapi.ea2node(int(ea)) if hasattr(idaapi, 'ea2node') else int(ea), NALT_AFLAGS)
        if len(mask) < 2:
            return idaapi.as_uint32(operator.and_(result, *mask) if mask else result)

        # Set the additional flags for the item at address `ea` using the provided `mask` and `value`.
        [mask, value] = mask
        preserve, value = idaapi.as_uint32(~mask), idaapi.as_uint32(-1 if value else 0) if isinstance(value, internal.types.bool) else idaapi.as_uint32(value)
        flags = (result & preserve) | (value & mask)
        idaapi.set_aflags(int(ea), flags) if hasattr(idaapi, 'set_aflags') else internal.netnode.alt.set(idaapi.ea2node(int(ea)) if hasattr(idaapi, 'ea2node') else int(ea), NALT_AFLAGS, flags)
        return result & mask

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

    @classmethod
    def has_typeinfo(cls, id):
        '''Return whether the address or identifier in `id` has type information associated with it.'''
        get_tinfo = (lambda ti, ea: idaapi.get_tinfo2(ea, ti)) if idaapi.__version__ < 7.0 else idaapi.get_tinfo
        return True if get_tinfo(idaapi.tinfo_t(), int(id)) else False

    @classmethod
    def guessed_typeinfo(cls, id, *origin):
        '''Return whether the address or identifier in `id` has guessed type information associated with it.'''
        id, flags, AFL_TYPE_GUESSED = int(id), idaapi.AFL_USERTI, getattr(idaapi, 'AFL_TYPE_GUESSED', 0xC2000000)
        res = node.aflags(id, operator.or_(flags, AFL_TYPE_GUESSED if origin else 0))
        guessed = cls.has_typeinfo(id) and not res
        if not origin:
            return True if guessed else False
        elif len(origin) != 1:
            raise internal.exceptions.InvalidParameterError(u"{:s}.guessed_typeinfo({:#x}{:s}) : An unsupported number of parameters ({:d}) was provided to the specified function.".format('.'.join([__name__, cls.__name__]), id, ", {:s}".format(', '.join(map("{!r}".format, origin))), len(origin)))
        [whom] = origin
        iterable = itertools.chain([whom] if isinstance(whom, internal.types.integer) else whom)
        unsigned = {idaapi.as_uint32(candidate) for candidate in iterable}
        return res & AFL_TYPE_GUESSED in unsigned

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
            if isinstance(item, internal.types.integer) or hasattr(item, '__int__'):
                offset += int(item)

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

    @classmethod
    def members(cls, sptr, slice):
        '''Select the contiguous members of the structure `sptr` using the given `slice` and return a tuple containing the start offset, stop offset, and ordered list containing each ``idaapi.member_t`` or each size.'''
        is_variable, is_frame = (sptr.props & prop for prop in [idaapi.SF_VAR, idaapi.SF_FRAME])
        members = [sptr.get_member(index) for index in builtins.range(sptr.memqty)]
        size = idaapi.get_struc_size(sptr)
        slice = slice if isinstance(slice, builtins.slice) else builtins.slice(slice, 1 + slice or None)
        istart, istop, istep = slice.indices(len(members))
        indices = [index for index in builtins.range(istart, istop, istep)]

        # If the structure is a union, then our slice doesn't need to be
        # contiguous. So we can simply include the index and return it.
        if sptr.props & idaapi.SF_UNION:
            results = [members[index] for index in indices]
            sizes = [idaapi.get_member_size(mptr) for mptr in results]
            return min(sizes), max(sizes), [(mptr.soff, mptr) for mptr in results]

        # Add all the points and segments from the structure.
        iterable = itertools.chain(*((mptr.soff, mptr.eoff) for mptr in members))
        points = [point for point, duplicates in itertools.groupby(iterable)]
        segments, iterable = {}, ((mptr, mptr.soff, mptr.eoff) for mptr in members)
        points.insert(0, 0) if points and operator.lt(0, *points[:+1]) else points
        points.append(size) if points and operator.gt(size, *points[-1:]) else points
        for mptr, soff, eoff in iterable:
            segments[soff] = segments[eoff] = mptr

        # Now we can select the members that the user specified and use it to find out the
        # interval. We adjust it with another member in order to capture additional space.
        selected = [members[index] for index in indices]

        # If our selection is from left to right (ordered), then we treat it as
        # normal and be sure to include the empty space in front of the last member.
        if selected and istart <= istop:
            imaximum = 1 + max(indices)
            maximum = members[imaximum].soff if imaximum < len(members) else points[-1]
            start = bisect.bisect_left(points, points[0] if slice.start is None else selected[0].soff)
            stop = bisect.bisect_left(points, points[-1] if slice.stop is None else maximum) + 1

        # If the selection is from right to left (reversed), then we need to
        # invert our tests against the slice and adjust for the minimum point.
        elif selected:
            iminimum = min(indices)
            minimum = members[iminimum - 1].eoff if iminimum > 0 else points[0]
            start = bisect.bisect_left(points, points[0] if slice.stop is None else minimum)
            stop = bisect.bisect_left(points, points[-1] if slice.start is None else selected[0].eoff)

        # If we couldn't select anything, then use the boundaries of the
        # members that were within the requested slice to identify the points.
        elif members:
            sleft, sright = (slice.start, slice.stop) if istart <= istop else (slice.stop, slice.start)
            iterable = ((members[index].soff if index < len(members) else members[-1].eoff) for index in [istart, istop])
            minimum = min(points) if sleft is None else min(*iterable)
            iterable = ((members[index].eoff if index < len(members) else members[-1].eoff) for index in [istart, istop])
            maximum = max(points) if sright is None else max(*iterable)
            start = bisect.bisect_left(points, minimum)
            stop = bisect.bisect_left(points, maximum) + 1 if istart < istop else bisect.bisect_left(points, maximum)

        # Otherwise since there's no selection or even members, we have nothing to return.
        else:
            return 0, size, []

        # Now we need to figure out which direction to slice the elements in.
        step, point = -1 if istep < 0 else +1, 0 if start < 0 else points[start] if start < len(points) else size

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

class contiguous(object):
    """
    This namespace contains any useful functions that can be used
    to create and process a list of contiguous elements. This is
    intended to simplify lining up any of the supported types such
    structures, members, boundaries, locations, or explicit sizes.

    Each function within the namespace interacts with a list where
    each element of the list is the item that needs to be aligned,
    and the index of the element represents where in the contiguous
    items that the element is to be placed. None of the items in
    the returned list are modified in any way. Instead the new
    position of the item is returned as a tuple beginning with
    the item's calculated offset and followed by the item residing
    at the tuple's position.
    """

    @classmethod
    def size(cls, items):
        '''Return the total size of the given list of `items` containing structures, members, boundaries, locations, registers, and integers in `items`.'''
        size = {integer_t : internal.utils.fidentity for integer_t in internal.types.integer}

        # Start by building the lookup table that will map an individual item to its size.
        size[idaapi.member_t] = idaapi.get_member_size
        size[idaapi.struc_t] = idaapi.get_struc_size
        size[idaapi.func_t] = size[idaapi.range_t] = size[idaapi.segment_t] = range.size
        size[internal.structure.structure_t] = internal.utils.fcompose(operator.attrgetter('ptr'), idaapi.get_struc_size)
        size[internal.structure.members_t] = internal.utils.fcompose(operator.attrgetter('owner'), operator.attrgetter('ptr'), idaapi.get_struc_size)
        size[internal.structure.member_t] = internal.utils.fcompose(operator.attrgetter('ptr'), idaapi.get_member_size)
        size[bounds_t] = size[location_t] = size[register_t] = size[partialregister_t] = operator.attrgetter('size')
        size[idaapi.tinfo_t] = operator.methodcaller('get_size')

        # If we were given a string, then we need to try to parse it. We try it first with
        # a variable and if that doesn't work, we fallback to parsing it as a regular type.
        Fparse_type_declaration = lambda string: tinfo.parse(None, string, idaapi.PT_SIL|idaapi.PT_VAR)[-1] if tinfo.parse(None, string, idaapi.PT_SIL|idaapi.PT_VAR) else tinfo.parse(None, string, idaapi.PT_SIL)
        size[u''.__class__] = size[''.__class__] = internal.utils.fcompose(Fparse_type_declaration, internal.utils.fcondition(operator.truth)(operator.methodcaller('get_size'), 0))

        # Before doing anything, convert our parameter into a list that we can process.
        items = [(item if item.__class__ in size else typemap.size(item)) for item in items]
        if not all(item.__class__ in size for item in items):
            missed = [internal.utils.pycompat.fullname(item.__class__) for item in items if item.__class__ not in size]
            iterable = itertools.chain(missed[:-1], map("and {:s}".format, missed[-1:])) if len(missed) > 1 else missed
            raise internal.exceptions.InvalidParameterError(u"{:s}.size({!r}) : Unable to determine the size for unsupported type{:s} ({:s}).".format('.'.join([__name__, cls.__name__]), items, '' if len(missed) == 1 else 's', ', '.join(iterable) if len(missed) > 2 else ' '.join(iterable)))

        # Then we only need to convert each item to a size, and then total the result.
        iterable = ((size[item.__class__], item) for item in items)
        return sum(F(item) for F, item in iterable)

    @classmethod
    def layout(cls, offset, items, direction=0):
        '''Yield the offset and item for each of the given `items` when laid out contiguously in the specified `direction` from `offset`.'''
        size = {integer_t : internal.utils.fidentity for integer_t in internal.types.integer}

        # Start by building the lookup table that will map an individual item to its size.
        size[idaapi.member_t] = idaapi.get_member_size
        size[idaapi.struc_t] = idaapi.get_struc_size
        size[idaapi.func_t] = size[idaapi.range_t] = size[idaapi.segment_t] = range.size
        size[internal.structure.structure_t] = internal.utils.fcompose(operator.attrgetter('ptr'), idaapi.get_struc_size)
        size[internal.structure.members_t] = internal.utils.fcompose(operator.attrgetter('owner'), operator.attrgetter('ptr'), idaapi.get_struc_size)
        size[internal.structure.member_t] = internal.utils.fcompose(operator.attrgetter('ptr'), idaapi.get_member_size)
        size[bounds_t] = size[location_t] = size[register_t] = size[partialregister_t] = operator.attrgetter('size')
        size[idaapi.tinfo_t] = operator.methodcaller('get_size')

        # If we were given a string, then we need to try to parse it. We first attempt to parse
        # it with a variable name first, and if that doesn't work we fall back to a regular type.
        Fparse_type_declaration = lambda string: tinfo.parse(None, string, idaapi.PT_SIL|idaapi.PT_VAR)[-1] if tinfo.parse(None, string, idaapi.PT_SIL|idaapi.PT_VAR) else tinfo.parse(None, string, idaapi.PT_SIL)
        size[u''.__class__] = size[''.__class__] = internal.utils.fcompose(Fparse_type_declaration, internal.utils.fcondition(operator.truth)(operator.methodcaller('get_size'), 0))

        # Listify our items and ensure that all of them are a type that we support.
        items = [(item if item.__class__ in size else typemap.size(item), item) for item in items]
        if not all(item.__class__ in size for item, _ in items):
            missed = [internal.utils.pycompat.fullname(item.__class__) for item, _ in items if item.__class__ not in size]
            iterable = itertools.chain(missed[:-1], map("and {:s}".format, missed[-1:])) if len(missed) > 1 else missed
            raise internal.exceptions.InvalidParameterError(u"{:s}.layout({:d}, {!r}, {:d}) : Unable to determine the layout for the unsupported type{:s} ({:s}).".format('.'.join([__name__, cls.__name__]), offset, [original for _, original in items], direction, '' if len(missed) == 1 else 's', ', '.join(iterable) if len(missed) > 2 else ' '.join(iterable)))

        # If we're laying the list of items in reverse, then
        # we calculate the offset before yielding the item.
        if direction < 0:
            for item, original in items:
                res = size[item.__class__](item)
                offset += direction * res
                yield math.trunc(offset), original if isinstance(item, internal.types.integer) and isinstance(original, symbol_t) else original if isinstance(original, (internal.types.list, internal.types.tuple)) or (getattr(original, '__hash__', None) and original in typemap.typemap) else item
            return

        # Otherwise, we start at the current offset, and
        # adjust the offset for each item as it comes in.
        for item, original in items:
            res = size[item.__class__](item)
            yield math.trunc(offset), original if isinstance(item, internal.types.integer) and isinstance(original, symbol_t) else original if isinstance(original, (internal.types.list, internal.types.tuple)) or (getattr(original, '__hash__', None) and original in typemap.typemap) else item
            offset += direction * res
        return

    @classmethod
    def describe(cls, items):
        '''Yield a description for each one of the provided `items` that are laid out contiguously.'''
        area = idaapi.area_t if idaapi.__version__ < 7.0 else idaapi.range_t
        for item in items:
            if isinstance(item, internal.types.integer):
                yield "{:+#x}".format(item)
            elif isinstance(item, (internal.structure.structure_t, internal.structure.member_t, internal.structure.members_t, namedtypedtuple, symbol_t)):
                yield "{!s}".format(item if isinstance(item, (namedtypedtuple, symbol_t)) else (lambda item: "{:s}({:#x})".format(internal.netnode.name.get(item.id), item.id))(item.owner if isinstance(item, internal.structure.members_t) else item))
            elif isinstance(item, (idaapi.struc_t, idaapi.member_t)):
                yield "{:s}({:#x})".format(internal.utils.pycompat.fullname(item.__class__), item.id)
            elif isinstance(item, area):
                yield "{:s}({:s})".format(internal.utils.pycompat.fullname(item.__class__), range.bounds(item))
            elif isinstance(item, (idaapi.tinfo_t, internal.types.string)):
                yield "{:s}(\"{:s}\")".format(internal.utils.pycompat.fullname(idaapi.tinfo_t), internal.utils.string.escape("{!s}".format(item), '"'))
            else:
                yield "{!r}".format(item)
            continue
        return

    @classmethod
    def left(cls, offset, items):
        '''Bind the specified list of `items` contiguously as a list with the beginning of the first item aligned to the given `offset`.'''
        result, beginning, layout = [], int(offset), [item for item in items]
        for offset, item in cls.layout(beginning, layout, +1):
            if isinstance(item, (internal.structure.structure_t, idaapi.struc_t, internal.structure.members_t)):
                result.append(internal.structure.new(item.owner.id, offset).members if isinstance(item, internal.structure.members_t) else internal.structure.new(item.id, offset))
            elif isinstance(item, (internal.structure.member_t, idaapi.member_t)):
                mowner, mindex, mptr = internal.structure.members.by_identifier(None, item.id)
                result.append(internal.structure.new(mowner.id, offset - (0 if mptr.props & idaapi.MF_UNIMEM else mptr.soff)).members[mindex])
            elif isinstance(item, (bounds_t, location_t)):
                result.append(location_t(offset, item.size) if isinstance(item, location_t) else bounds_t(offset, offset + item.size))
            elif isinstance(item, idaapi.area_t if idaapi.__version__ < 7.0 else idaapi.range_t):
                result.append(range.bounds(item).range())
            else:
                result.append(item)
            continue
        return result

    @classmethod
    def right(cls, offset, items):
        '''Bind the specified list of `items` contiguously as a list with the end of the last item aligned to the given `offset`.'''
        result, ending, layout = [], int(offset), [item for item in items]
        for offset, item in cls.layout(ending, layout[::-1], -1):
            if isinstance(item, (internal.structure.structure_t, idaapi.struc_t, internal.structure.members_t)):
                result.append(internal.structure.new(item.owner.id, offset).members if isinstance(item, internal.structure.members_t) else internal.structure.new(item.id, offset))
            elif isinstance(item, (internal.structure.member_t, idaapi.member_t)):
                mowner, mindex, mptr = internal.structure.members.by_identifier(None, item.id)
                result.append(internal.structure.new(mowner.id, offset - (0 if mptr.props & idaapi.MF_UNIMEM else mptr.soff)).members[mindex])
            elif isinstance(item, (bounds_t, location_t)):
                result.append(location_t(offset, item.size) if isinstance(item, location_t) else bounds_t(offset, offset + item.size))
            elif isinstance(item, idaapi.area_t if idaapi.__version__ < 7.0 else idaapi.range_t):
                result.append(range.bounds(item).range())
            else:
                result.append(item)
            continue
        return result[::-1]

    @classmethod
    def has(cls, item):
        '''Return whether the specified `item` has an offset that can be used for a contiguous layout.'''
        type_has_offset = (idaapi.area_t if idaapi.__version__ < 7.0 else idaapi.range_t, internal.structure.structure_t, internal.structure.members_t, internal.structure.member_t, bounds_t, location_t)
        if isinstance(item, type_has_offset):
            return True
        elif isinstance(item, idaapi.struc_t):
            return True if item.props & idaapi.SF_FRAME else False
        elif isinstance(item, idaapi.member_t):
            return False if item.flag & getattr(idaapi, 'MF_UNIMEM', 2) else True
        return False

    @classmethod
    def start(cls, items):
        '''Return the starting offset for a list of `items` to be used for a contiguous layout.'''
        items = [item for item in items] if isinstance(items, internal.types.list) else [items]

        # if the first element in the list has an offset, then extract it.
        if items and all(map(cls.has, items[:+1])):
            [item] = items[:+1]

        # if there were no elements in the list or the first item
        # did not have an offset, then just assume that it is 0.
        else:
            return 0

        # figure out the offset for the extracted item and then return it.
        if isinstance(item, (internal.structure.structure_t, internal.structure.members_t)):
            offset = item.baseoffset if isinstance(item, internal.structure.members_t) else item.members.baseoffset
        elif isinstance(item, internal.structure.member_t):
            offset = item.offset
        elif isinstance(item, (bounds_t, location_t, idaapi.area_t if idaapi.__version__ < 7.0 else idaapi.range_t)):
            offset, _ = item.bounds if isinstance(item, location_t) else item if isinstance(item, namedtypedtuple) else range.unpack(item)

        # if the item is a structure or a member, then we need to check if it
        # is part of a frame. if it is, then we calculate its actual offset.
        elif isinstance(item, (idaapi.struc_t, idaapi.member_t)):
            mowner, mindex, mptr = internal.structure.members.by_identifier(None, item.id) if isinstance(item, idaapi.member_t) else (item, 0, None)
            ea, moffset = idaapi.get_func_by_frame(mowner.id), 0 if not mptr or mowner.props & idaapi.SF_UNION else mptr.soff
            offset = function.frame_offset(ea, moffset) if mowner.props & idaapi.SF_FRAME and ea != idaapi.BADADDR else moffset

        else:
            raise internal.exceptions.InvalidTypeOrValueError(u"{:s}.start({:s}) : Unable to determine the offset for the first item ({!r}) due to being an unsupported type ({!s}).".format('.'.join([__name__, cls.__name__]), "[{:s}]".format(', '.join(cls.describe(items))), item, item.__class__))
        return offset

    @classmethod
    def stop(cls, items):
        '''Return the ending offset for a list of `items` to be used for a contiguous layout.'''
        items = [item for item in items] if isinstance(items, internal.types.list) else [items]

        # if the last element in the list has an offset, then extract it.
        if items and all(map(cls.has, items[-1:])):
            [item] = items[-1:]

        # if there were no elements in the list or the last item
        # did not have an offset, then we can just use the size.
        else:
            return cls.size(items)

        # figure out the offset for the right side of the first item with an offset, and
        # add it to the total size of the selected elements that don't have an offset.
        if isinstance(item, (internal.structure.structure_t, internal.structure.members_t)):
            offset = sum([item.baseoffset, item.owner.size]) if isinstance(item, internal.structure.members_t) else sum([item.members.baseoffset, item.size])
        elif isinstance(item, internal.structure.member_t):
            offset = item.offset + idaapi.get_member_size(item.ptr)
        elif isinstance(item, (bounds_t, location_t, idaapi.area_t if idaapi.__version__ < 7.0 else idaapi.range_t)):
            _, offset = item.bounds if isinstance(item, location_t) else item if isinstance(item, namedtypedtuple) else range.unpack(item)

        # if we're dealing with a native structure or member, then we have to
        # check whether it's referencing a frame to calculate its real offset.
        elif isinstance(item, (idaapi.struc_t, idaapi.member_t)):
            mowner, mindex, mptr = internal.structure.members.by_identifier(None, item.id) if isinstance(item, idaapi.member_t) else (item, 0, None)
            ea, moffset = idaapi.get_func_by_frame(mowner.id), mptr.eoff if mptr else idaapi.get_struc_size(item)
            offset = function.frame_offset(ea, moffset) if mowner.props & idaapi.SF_FRAME and ea != idaapi.BADADDR else moffset

        else:
            raise internal.exceptions.InvalidTypeOrValueError(u"{:s}.stop({:s}) : Unable to determine the offset for the last item ({!r}) due to being an unsupported type ({!s}).".format('.'.join([__name__, cls.__name__]), "[{:s}]".format(', '.join(cls.describe(items))), item, item.__class__))
        return offset

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
                    reg = architecture.by_partial(reg, 8 * regoff, 8 * size)
            except KeyError:
                reg = architecture.by_partial(ridx1, 8 * regoff, 8 * size)
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
    def function_details(cls, func, *type):
        '''Given a function location in `func` and its `type` information, return the ``idaapi.tinfo_t`` and the ``idaapi.func_type_data_t`` that is associated with it.'''
        [tinfo] = type if type else [function.typeinfo(func)]
        tinfo = ti = function.typeinfo(func) if tinfo is None else tinfo
        if tinfo is None:
            _, ea = addressOfRuntimeOrStatic(func)
            raise internal.exceptions.MissingTypeOrAttribute(u"{:s}.function_details({:#x}{:s}) : Unable to get the prototype for the specified function ({:#x}).".format('.'.join([__name__, cls.__name__]), ea, ", {!r}".format("{!s}".format(*type)) if type else '', ea))
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

        # If our address is runtime and our type is a function (not a pointer),
        # then the type is incorrect. This can happen when the disassembler infers
        # the type from the name. We support this so we can warn the user about it.
        elif rt and ti.is_func():
            tinfo = ti
            logging.info(u"{:s}.function_details({:#x}, {!r}) : Ignoring non-pointer function type applied to the specified runtime address ({:#x}).".format('.'.join([__name__, cls.__name__]), ea, "{!s}".format(ti), ea))

        # Anything else is a type error that we need to raise to the user.
        else:
            raise internal.exceptions.InvalidTypeOrValueError(u"{:s}.function_details({:#x}, {!r}) : The type that was received ({!r}) for the specified function ({:#x}) was not a function type.".format('.'.join([__name__, cls.__name__]), ea, "{!s}".format(ti), "{!s}".format(ti), ea))

        # Now we can check to see if the type has details that we can grab the
        # argument type out of. If there are no details, then we raise an
        # exception informing the user.
        if not tinfo.has_details():
            raise internal.exceptions.MissingTypeOrAttribute(u"{:s}.function_details({:#x}, {!r}) : The type information ({!r}) for the specified function ({:#x}) does not contain any details.".format('.'.join([__name__, cls.__name__]), ea, "{!s}".format(ti), "{!s}".format(tinfo), ea))

        # Before returning the type, we concretize it as it might be exported.
        til, old, new = cls.library(tinfo), tinfo, cls.copy(tinfo)
        res = idaapi.replace_ordinal_typerefs(til, new) if hasattr(idaapi, 'replace_ordinal_typerefs') else 0
        if res < 0:
            logging.debug(u"{:s}.function_details({:#x}, {!r}) : Ignoring error {:d} while trying to concretize the type \"{:s}\" for the function at {:#x}.".format('.'.join([cls.__name__, cls.__name__]), ea, "{!s}".format(ti), res, internal.utils.string.escape("{!s}".format(tinfo), '"'), ea))
        tinfo = old if res < 0 else new

        # Now we can grab our function details and return them to the caller. If we
        # couldn't get them the first time, then it's probably due to the layout.
        ftd = idaapi.func_type_data_t()
        if tinfo.get_func_details(ftd):
            return tinfo, ftd

        elif not tinfo.get_func_details(ftd, idaapi.GTD_NO_ARGLOCS):
            raise internal.exceptions.DisassemblerError(u"{:s}.function_details({:#x}, {!r}) : Unable to get the details from the type information ({!r}) for the specified function ({:#x}).".format('.'.join([__name__, cls.__name__]), ea, "{!s}".format(ti), "{!s}".format(tinfo), ea))

        logging.info(u"{:s}.function_details({:#x}, {!r}) : Unable to calculate the argument locations from the type ({!r}) for the specified function ({:#x}).".format('.'.join([__name__, cls.__name__]), ea, "{!s}".format(ti), "{!s}".format(tinfo), ea))
        return tinfo, ftd

    @classmethod
    def prototype_details(cls, type):
        '''Given a function prototype in `type`, return the ``idaapi.tinfo_t`` and the ``idaapi.func_type_data_t`` that is associated with it.'''
        info, wrapped = type, []
        while info.is_ptr():
            wrapped.append(info)
            info = info.get_pointed_object()

        # Verify that it is actually a function prototype.
        if not any([info.is_func(), info.is_funcptr()]):
            raise internal.exceptions.InvalidTypeOrValueError(u"{:s}.prototype_details({!r}) : The resolved type information \"{:s}\" is not a function prototype and does not contain any arguments.".format('.'.join([__name__, cls.__name__]), "{!s}".format(type), internal.utils.string.escape("{!s}".format(info), '"')))

        # ...and make sure it has details that we can use.
        elif not info.has_details():
            raise internal.exceptions.MissingTypeOrAttribute(u"{:s}.prototype_details({!r}) : The resolved type information \"{:s}\" does not contain any details.".format('.'.join([__name__, cls.__name__]), "{!s}".format(type), internal.utils.string.escape("{!s}".format(info), '"')))

        # Now we can grab our function details from the type information.
        ftd = idaapi.func_type_data_t()
        ok = info.get_func_details(ftd)
        if not ok and not info.get_func_details(ftd, idaapi.GTD_NO_ARGLOCS):
            raise internal.exceptions.DisassemblerError(u"{:s}.prototype_details({{!r}) : Unable to get the function details from the resolved prototype ({!r}).".format('.'.join([__name__, cls.__name__]), "{!s}".format(type), "{!s}".format(info)))

        elif not ok:
            logging.info(u"{:s}.prototype_details({!r}) : Unable to calculate the argument locations for the resolved prototype ({!r}).".format('.'.join([__name__, cls.__name__]), "{!s}".format(type), "{!s}".format(info)))

        # Concretize the type that we're returning in case the caller wants to save it.
        til, old, new = cls.library(info), info, cls.copy(info)
        res = idaapi.replace_ordinal_typerefs(til, info) if hasattr(idaapi, 'replace_ordinal_typerefs') else 0
        if res < 0:
            logging.debug(u"{:s}.prototype_details({!r}) : Ignoring error {:d} while trying to concretize the function prototype \"{:s}\".".format('.'.join([cls.__name__, cls.__name__]), "{!s}".format(type), res, internal.utils.string.escape("{!s}".format(info), '"')))
        info = old if res < 0 else new
        return info, ftd

    @classmethod
    def update_prototype_details(cls, type):
        '''Given a function prototype in `type`, yield the ``idaapi.tinfo_t`` and the ``idaapi.func_type_data_t`` that is associated with it and then update the prototype with the ``idaapi.func_type_data_t`` that is sent back.'''
        info, wrapped = type, []
        while info.is_ptr():
            wrapped.append(info)
            info = info.get_pointed_object()

        # Verify that it is actually a function prototype.
        if not any([info.is_func(), info.is_funcptr()]):
            raise internal.exceptions.InvalidTypeOrValueError(u"{:s}.update_prototype_details({!r}) : The resolved type information \"{:s}\" is not a function prototype and does not contain any arguments.".format('.'.join([__name__, cls.__name__]), "{!s}".format(type), internal.utils.string.escape("{!s}".format(info), '"')))

        # ...and make sure it has details that we can use.
        elif not info.has_details():
            raise internal.exceptions.MissingTypeOrAttribute(u"{:s}.update_prototype_details({!r}) : The resolved type information \"{:s}\" does not contain any details.".format('.'.join([__name__, cls.__name__]), "{!s}".format(type), internal.utils.string.escape("{!s}".format(info), '"')))

        # Now we can grab our function details from the type information.
        ftd = idaapi.func_type_data_t()
        ok = info.get_func_details(ftd)
        if not ok and not info.get_func_details(ftd, idaapi.GTD_NO_ARGLOCS):
            raise internal.exceptions.DisassemblerError(u"{:s}.update_prototype_details({{!r}) : Unable to get the function details from the resolved prototype ({!r}).".format('.'.join([__name__, cls.__name__]), "{!s}".format(type), "{!s}".format(info)))

        elif not ok:
            logging.info(u"{:s}.update_prototype_details({!r}) : Unable to calculate the argument locations for the resolved prototype ({!r}).".format('.'.join([__name__, cls.__name__]), "{!s}".format(type), "{!s}".format(info)))

        # Concretize the type that we're yielding in case the caller wants to save it.
        til, old, new = cls.library(info), info, cls.copy(info)
        res = idaapi.replace_ordinal_typerefs(til, info) if hasattr(idaapi, 'replace_ordinal_typerefs') else 0
        if res < 0:
            logging.debug(u"{:s}.update_prototype_details({!r}) : Ignoring error {:d} while trying to concretize the function prototype \"{:s}\".".format('.'.join([cls.__name__, cls.__name__]), "{!s}".format(type), res, internal.utils.string.escape("{!s}".format(info), '"')))
        info = old if res < 0 else new

        # Yield the function type along with the details to the caller and then
        # receive one back (tit-for-tat) which we'll use to re-create the tinfo_t.
        td = (yield (info, ftd))
        if not info.create_func(td):
            raise internal.exceptions.DisassemblerError(u"{:s}.update_prototype_details({!r}) : Unable to modify the function details for the specified prototype ({!r}).".format('.'.join([__name__, cls.__name__]), "{!s}".format(type), "{!s}".format(info)))

        # Now we need to re-wrap the type using the layers that we preserved.
        res = idaapi.tinfo_t()
        for ti in wrapped[::-1]:
            td = idaapi.ptr_type_data_t()
            if not ti.get_ptr_details(td):
                raise internal.exceptions.DisassemblerError(u"{:s}.update_prototype_details({!r}) : The preserved type \"{:s}\" does not contain the pointer details that were expected.".format('.'.join([__name__, cls.__name__]), "{!s}".format(type), internal.utils.string.escape("{!s}".format(ti), '"')))

            # Attach our resulting type to whatever pointer we collected.
            td.obj_type = info
            if not res.create_ptr(td):
                raise internal.exceptions.DisassemblerError(u"{:s}.update_prototype_details({!r}) : Unable to create a pointer for the currently nested type \"{:s}\".".format('.'.join([__name__, cls.__name__]), "{!s}".format(type), internal.utils.string.escape("{!s".format(info), '"')))
            info = res

        # Before yielding our wrapped type, we need to concretize before yielding.
        til, oldinfo, newinfo = cls.library(info), info, cls.copy(info)
        res = idaapi.replace_ordinal_typerefs(til, newinfo) if hasattr(idaapi, 'replace_ordinal_typerefs') else 0
        if res < 0:
            logging.debug(u"{:s}.update_prototype_details({!r}) : Ignoring error {:d} while trying to concretize the function prototype \"{:s}\".".format('.'.join([cls.__name__, cls.__name__]), "{!s}".format(type), res, internal.utils.string.escape("{!s}".format(info), '"')))
        newinfo = oldinfo if res < 0 else newinfo

        # We're done, so keep generating the result until the caller closes us.
        try:
            while True:
                td = yield (newinfo, td)

        # I love you, but good bye. I looove you, but good bye. A
        # bird with clipped wings can still sing but no longer fly.
        except GeneratorExit:
            pass
        return

    @classmethod
    def update_function_details(cls, func, ti=None, *flags):
        '''Given a function location in `func` and its type information as `ti`, yield the ``idaapi.tinfo_t`` and the ``idaapi.func_type_data_t`` that is associated with it and then update the function with the `flags` and ``idaapi.func_type_data_t`` that is sent back.'''
        apply_tinfo = idaapi.apply_tinfo2 if idaapi.__version__ < 7.0 else idaapi.apply_tinfo

        # If we weren't given a type, then we need to figure it out ourselves.
        rt, ea = addressOfRuntimeOrStatic(func)
        tinfo = function.typeinfo(func) if ti is None else ti
        if tinfo is None:
            raise internal.exceptions.DisassemblerError(u"{:s}.update_function_details({:#x}, {!s}) : Unable to get the prototype for the specified function ({:#x}).".format('.'.join([__name__, cls.__name__]), ea, "{!s}".format(ti), ea))
        ti = tinfo

        # Similar to function_details, we first need to figure out if our type is a
        # function so that we can dereference it to get the information that we yield.
        if rt and ti.is_funcptr():
            pi = idaapi.ptr_type_data_t()
            if not ti.get_ptr_details(pi):
                raise internal.exceptions.DisassemblerError(u"{:s}.update_function_details({:#x}, {!r}) : Unable to get the pointer target from the type ({!r}) at the specified address ({:#x}).".format('.'.join([__name__, cls.__name__]), ea, "{!s}".format(ti), "{!s}".format(ti), ea))
            info = pi.obj_type

        # If the previous case failed, then we're our type isn't related to a function
        # and we were used on a non-callable address. If this is the case, then we need
        # to raise an exception to let the user know exactly what happened.
        elif rt and ti.is_ptr():
            info = ti.get_pointed_object()
            raise internal.exceptions.MissingTypeOrAttribute(u"{:s}.update_function_details({:#x}, {!r}) : The target of the pointer type ({!r}) at the specified address ({:#x}) is not a function.".format('.'.join([__name__, cls.__name__]), ea, "{!s}".format(ti), "{!s}".format(info), ea))

        # Otherwise this a function and we just use the idaapi.tinfo_t that we got.
        elif not rt and ti.is_func():
            info = ti

        # If it's runtime-linked and a function instead of a pointer, then throw
        # up a warning that we will be correcting it by promoting it to a pointer.
        elif rt and ti.is_func() and not ti.is_ptr():
            logging.warning(u"{:s}.update_function_details({:#x}, {!r}) : The type ({!r}) for the runtime-linked function at {:#x} is not a function pointer and will be corrected during modification.".format('.'.join([__name__, cls.__name__]), ea, "{!s}".format(ti), "{!s}".format(ti), ea))
            pi, info = idaapi.ptr_type_data_t(), ti

        # Anything else is a type error that we need to raise to the user.
        else:
            raise internal.exceptions.MissingTypeOrAttribute(u"{:s}.update_function_details({:#x}, {!r}) : The type that was received ({!r}) for the specified function ({:#x}) was not a function type.".format('.'.join([__name__, cls.__name__]), ea, "{!s}".format(ti), "{!s}".format(ti), ea))

        # Next we need to ensure that the type information has details that
        # we can modify. If they aren't there, then we need to bail.
        if not info.has_details():
            raise internal.exceptions.MissingTypeOrAttribute(u"{:s}.update_function_details({:#x}, {!r}) : The type information ({!r}) for the specified function ({:#x}) does not contain any details.".format('.'.join([__name__, cls.__name__]), ea, "{!s}".format(ti), "{!s}".format(info), ea))

        # Now we can grab our function details from the snagged type information.
        ftd = idaapi.func_type_data_t()
        ok = info.get_func_details(ftd)
        if not ok and not info.get_func_details(ftd, idaapi.GTD_NO_ARGLOCS):
            raise internal.exceptions.DisassemblerError(u"{:s}.update_function_details({:#x}, {!r}) : Unable to get the details from the type information ({!r}) for the specified function ({:#x}).".format('.'.join([__name__, cls.__name__]), ea, "{!s}".format(ti), "{!s}".format(info), ea))

        elif not ok:
            logging.info(u"{:s}.update_function_details({:#x}, {!r}) : Unable to calculate the argument locations from the type ({!r}) for the specified function ({:#x}).".format('.'.join([__name__, cls.__name__]), ea, "{!s}".format(ti), "{!s}".format(info), ea))

        # Concretize the type that we're yielding in case the caller wants to save it.
        til, old, new = cls.library(info), info, cls.copy(info)
        res = idaapi.replace_ordinal_typerefs(til, info) if hasattr(idaapi, 'replace_ordinal_typerefs') else 0
        if res < 0:
            logging.debug(u"{:s}.update_function_details({:#x}, {!r}) : Ignoring error {:d} while trying to concretize the type \"{:s}\" for the function at {:#x}.".format('.'.join([cls.__name__, cls.__name__]), ea, "{!s}".format(info), res, internal.utils.string.escape("{!s}".format(info), '"'), ea))
        info = old if res < 0 else new

        # Yield the function type along with the details to the caller and then
        # receive one back (tit-for-tat) which we'll use to re-create the tinfo_t
        # that we'll apply back to the address.
        ftd = (yield (info, ftd))
        if not info.create_func(ftd):
            raise internal.exceptions.DisassemblerError(u"{:s}.update_function_details({:#x}, {!r}) : Unable to modify the type information ({!r}) for the specified function ({:#x}).".format('.'.join([__name__, cls.__name__]), ea, "{!s}".format(ti), "{!s}".format(info), ea))

        # If we were a runtime-linked address, then we're a pointer and we need
        # to re-create it for our tinfo_t.
        if rt:
            pi.obj_type = info
            if not ti.create_ptr(pi):
                raise internal.exceptions.DisassemblerError(u"{:s}.update_function_details({:#x}, {!r}) : Unable to modify the pointer target in the type information ({!r}) for the specified function ({:#x}).".format('.'.join([__name__, cls.__name__]), ea, "{!s}".format(info), "{!s}".format(info), ea))
            newinfo = ti

        # If it wasn't a runtime function, then we're fine and can just apply the
        # tinfo that we started out using.
        else:
            newinfo = info

        # Now we need to check the aflags for the address in order to determine the default
        # flags to use when applying the type. If the decompiler guessed it, then to override,
        # we need to set it definitively. Otherwise, we use AFL_USERTI distinguish the guess.
        guessed = node.aflags(ea, idaapi.AFL_TYPE_GUESSED if hasattr(idaapi, 'AFL_TYPE_GUESSED') else idaapi.AFL_USERTI)
        definitive = True if guessed == idaapi.AFL_USERTI or guessed & getattr(idaapi, 'AFL_HR_DETERMINED', 0xC0000000) else False
        [tflags] = itertools.chain(flags if flags else [idaapi.TINFO_DEFINITE if definitive else idaapi.TINFO_GUESSED])

        # Finally we have a proper idaapi.tinfo_t that we can apply. After we apply it,
        # all we need to do is return the previous one to the caller and we're good.
        if not apply_tinfo(ea, newinfo, tflags):
            raise internal.exceptions.DisassemblerError(u"{:s}.update_function_details({:#x}, {!r}) : Unable to apply the new type information ({!r}) to the specified function ({:#x}).".format('.'.join([__name__, cls.__name__]), ea, "{!s}".format(info), "{!s}".format(newinfo), ea))

        # Same thing as every other type, we try to concretize prior to yielding it.
        til, oldinfo, newinfo = cls.library(newinfo), newinfo, cls.copy(newinfo)
        res = idaapi.replace_ordinal_typerefs(til, newinfo) if hasattr(idaapi, 'replace_ordinal_typerefs') else 0
        if res < 0:
            logging.debug(u"{:s}.update_function_details({:#x}, {!r}) : Ignoring error {:d} while trying to concretize the type \"{:s}\" for the function at {:#x}.".format('.'.join([cls.__name__, cls.__name__]), ea, "{!s}".format(info), res, internal.utils.string.escape("{!s}".format(newinfo), '"'), ea))
        newinfo = oldinfo if res < 0 else newinfo

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

    @classmethod
    def format_library(cls, library, *name):
        '''Return a string describing the specified type `library` along with an ordinal or `name` if one is given.'''
        lclass, description = library.__class__, library.desc
        if not name:
            return "<{:s}; <{:s}>>".format('.'.join([lclass.__module__, lclass.__name__]), internal.utils.string.of(description))

        # if we were given a name or an ordinal, then we'll include that too.
        tclass, [ordinal_or_name] = idaapi.tinfo_t, name

        if isinstance(ordinal_or_name, internal.types.string):
            ordinal, name = idaapi.get_type_ordinal(library, internal.utils.string.to(ordinal_or_name)), ordinal_or_name
            return "<{:s}; #{:s} \"{:s}\">".format('.'.join([lclass.__module__, lclass.__name__]), "{:d}".format(ordinal) if ordinal else '???', name)

        ordinal, name = ordinal_or_name, internal.utils.string.of(idaapi.get_numbered_type_name(library, ordinal_or_name))
        if idaapi.get_type_ordinal(library, internal.utils.string.to(name or '')) == ordinal:
            return "<{:s}; #{:d} \"{:s}\">".format('.'.join([lclass.__module__, lclass.__name__]), ordinal, name)

        count = cls.quantity(library)
        if name is None:
            return "<{:s}; #{:s}>".format('.'.join([lclass.__module__, lclass.__name__]), "{:d}".format(ordinal) if 0 < ordinal < count else '???')
        return "<{:s}; #{:s} \"{:s}\">".format('.'.join([lclass.__module__, lclass.__name__]), "{:d}".format(ordinal) if 0 < ordinal < count else '???', name)

    @classmethod
    def library(cls, type=None):
        '''Return the type library belonging to the specified type or the default type library for the database.'''
        til = None if type is None else type.get_til() if hasattr(type, 'get_til') else None
        try:
            library = til if til is not None else idaapi.cvar.idati if idaapi.__version__ < 7.0 else idaapi.get_idati()
            assert(library)
        except (RuntimeError, AssertionError):
            library = idaapi.til_t()
        return library

    @classmethod
    def quantity(cls, *library):
        '''Return the number of ordinals within the specified type `library`.'''
        [til] = library if library else [cls.library()]
        res = idaapi.get_ordinal_qty(til) if idaapi.__version__ < 8.4 else idaapi.get_ordinal_limit(til)
        return -1 if idaapi.as_signed(res) == -1 else res

    @classmethod
    def iterate(cls, *library):
        '''Iterate through the types within the specified type `library`.'''
        [til] = library if library else [cls.library()]
        for ordinal in builtins.range(1, cls.quantity(til)):
            name, ti = idaapi.get_numbered_type_name(til, ordinal), cls.at_ordinal(ordinal, til)
            yield ordinal, internal.utils.string.of(name or ''), ti
        return

    @classmethod
    def size(cls, type, *variable):
        '''Return the size of the specified `type` as an integer or a pythonic atom if `variable` is true.'''
        realtype, size, [use_atom] = type.get_realtype(), type.get_size(), variable if variable else [False]
        if not use_atom:
            return 0 if size in {0, idaapi.BADSIZE} else size
        elif realtype in {idaapi.BT_VOID}:
            return 0
        elif type.is_array() and not type.get_array_nelems():
            return Ellipsis
        return None if size in {idaapi.BADSIZE} else size

    @classmethod
    def copy(cls, type, *library):
        '''Return a copy of the given `type` from the specified type library.'''
        if isinstance(type, idaapi.tinfo_t) and hasattr(type, 'copy'):
            return type.copy()

        # First try and determine the type library that is needed for deserialization.
        elif isinstance(type, idaapi.tinfo_t):
            ti = idaapi.tinfo_t()
            [til] = library if library else [cls.library(type)]

            # Now we serialize the type, and then deserialize it afterwards.
            serialized = type.serialize()
            if not ti.deserialize(til, *serialized):
                description = "{:s}<{:s}>".format(internal.utils.pycompat.fullname(til.__class__), til.desc or '') if til and til.desc else "{!s}".format(til)
                raise internal.exceptions.DisassemblerError(u"{:s}.copy({!r}, {:s}) : Unable to use the serialized information from the type ({!r}) to make a copy of it.".format('.'.join([__name__, cls.__name__]), "{!s}".format(type), description, serialized))
            return ti
        return

    @classmethod
    def concretize(cls, type, *library):
        '''Return the specified `type` with its ordinals resolved to names from the given type library.'''

        # If we were not given a type, then return it as-is.
        if not isinstance(type, idaapi.tinfo_t):
            return type

        # First we need to figure out what library the type is from.
        [til] = library if library else [cls.library(type)]

        # Then we can call the replace_ordinal_typerefs function, because what this does.
        new = cls.copy(type, til)
        res = idaapi.replace_ordinal_typerefs(til, new) if hasattr(idaapi, 'replace_ordinal_typerefs') else 0

        # If we failed, then log something..but silently (sorta). This is an
        # internal function and is intended to be abstracted away from the user.
        if res < 0:
            description = "{:s}<{:s}>".format(internal.utils.pycompat.fullname(til.__class__), til.desc or '') if til and til.desc else "{!s}".format(til)
            logging.debug(u"{:s}.concretize({!r}, {!s}) : Returning the non-concrete type for \"{!s}\" due to an error being returned (error {:d}).".format('.'.join([cls.__name__, cls.__name__]), "{!s}".format(type), description, internal.utils.string.escape("{!s}".format(type), '"'), res))
        return type if res < 0 else new

    @classmethod
    def reference(cls, ordinal, *library):
        '''Return a type reference for the given `ordinal` belonging to the specified type `library`.'''
        ti, [til] = idaapi.tinfo_t(), library if library else [cls.library()]

        # create an empty typedef_type_data_t, so that we can assign its fields.
        td = idaapi.typedef_type_data_t(til, 0, True)

        # populate the typedef_type_data_t with either a string or an integer.
        if isinstance(ordinal, internal.types.string):
            td.is_ordref, td.name = False, internal.utils.string.to(ordinal)
        else:
            td.is_ordref, td.ordinal = True, ordinal

        # now we can populate the tinfo_t and then concretize it before returning it.
        ok = ti.create_typedef(td)

        # if we were given a library or an ordinal, then explicitly strip out
        # the ordinal for an actual name in order to always return a named type.
        if library or isinstance(ordinal, internal.types.integer):
            res = idaapi.replace_ordinal_typerefs(til, ti) if ok and hasattr(idaapi, 'replace_ordinal_typerefs') else 0
            return ti if ok and res >= 0 else None

        # if we were given a string with no library, then we return a named type
        # without attempting to resolve it. this allows returning a fake typeref.
        return ti if ok else ti

    @classmethod
    def ordinal(cls, type, *library):
        '''Return the ordinal for the given `type` from the specified type `library`.'''
        ti, [til] = type, library if library else [None]

        # first try to get the ordinal naturally and verify that it exists.
        ordinal = ti.get_ordinal()
        if ordinal and til:
            return ordinal if cls.get_numbered_type(til, ordinal) else 0

        elif ordinal:
            return ordinal

        # if it was concretized, then there is no ordinal and it's stored
        # as a typename. if there isn't a typename, though, then abort.
        elif not ti.get_type_name():
            return ti.get_final_ordinal()

        # since it's using a typename, we need to search the type library for it.
        name = internal.utils.string.of(ti.get_type_name())
        serialized = cls.get_named_type(til if til else cls.library(type), internal.utils.string.to(name), idaapi.NTF_TYPE)
        if not serialized:
            return ti.get_final_ordinal()

        # the last item from get_named_type's result contains our ordinal.
        defaults = [0, b'', b'', b'', b'', getattr(idaapi, 'sc_unk', 0), 0]
        error, type, fields, cmt, fields_cmt, sclass, ordinal = [item for item in itertools.chain(serialized, defaults[len(serialized) - len(defaults):])][:len(defaults)]
        return ordinal

    @classmethod
    def get(cls, library, *serialized):
        '''Return a type for the `serialized` type information from a specific type `library`.'''
        type, fields, cmt, fieldcmts, sclass = itertools.chain(serialized, [b'\x01', b'', b'', b'', getattr(idaapi, 'sc_unk', 0)][len(serialized) - 5:] if len(serialized) < 5 else [])

        # ugh..because ida can return a non-bytes as one of the comments, we
        # need to convert it so that the api will fucking understand us.
        res = cmt or fieldcmts or b''
        comments = res if isinstance(res, internal.types.bytes) else res.encode('latin1')

        # try and deserialize the type information so that we can return it.
        ti, til = idaapi.tinfo_t(), library if library else cls.library()
        if ti.deserialize(til, bytes(type or b''), bytes(fields or b''), bytes(comments or b'')):
            return ti if hasattr(idaapi, 'replace_ordinal_typerefs') and idaapi.replace_ordinal_typerefs(til, ti) >= 0 else ti

        # if we failed deserializing the type, then it's probably
        # because of the comments. so, we try again without them.
        description = "{:s}<{:s}>".format(internal.utils.pycompat.fullname(til.__class__), til.desc or '') if til and til.desc else "{!s}".format(til)
        logging.debug(u"{:s}.get({!s}, {!r}) : Retrying the deserialization for the given type without its comments ({!r}).".format('.'.join([__name__, cls.__name__]), description, serialized, comments))
        if not ti.deserialize(til, bytes(type or b''), bytes(fields or b'')):
            return None
        return ti if hasattr(idaapi, 'replace_ordinal_typerefs') and idaapi.replace_ordinal_typerefs(til, ti) >= 0 else ti

    @classmethod
    def decode_bytes(cls, bytes):
        '''Decode the given `bytes` into a list containing the length and the bytes for each encoded string.'''
        ok, results, iterable = True, [], (ord for ord in bytearray(bytes))

        integer = next(iterable, None)
        length_plus_one, ok = integer or 0, False if integer is None else True
        while ok:
            one = 1 if length_plus_one < 0x7f else next(iterable, None)
            assert((one == 1) and length_plus_one > 0)
            encoded = bytearray(ord for index, ord in zip(builtins.range(length_plus_one - 1), iterable))
            results.append((length_plus_one - 1, encoded)) if ok else None

            integer = next(iterable, None)
            length_plus_one, ok = integer or 0, False if integer is None else True
        return results

    @classmethod
    def encode_bytes(cls, strings):
        '''Encode the list of `strings` with their lengths and return them as bytes.'''
        encode_length = lambda integer: bytearray([integer + 1] if integer + 1 < 0x80 else [integer + 1, 1])
        iterable = (bytes(string) if isinstance(string, (bytes, bytearray)) else string.encode('utf-8') for string in strings)
        pairs = ((len(chunk), chunk) for chunk in iterable)
        return bytes(bytearray().join(itertools.chain(*((encode_length(length), bytearray(chunk)) for length, chunk in pairs))))

    @classmethod
    def names(cls, type, *names):
        '''Return the names for the fields within the given `type` or return a new `type` if any `names` are given.'''
        library, serialized, description = type.get_til(), type.serialize(), "{!s}".format(type)
        type, fields, cmt, fieldcmts, sclass = itertools.chain(serialized, [b'\x01', b'', b'', b'', getattr(idaapi, 'sc_unk', 0)][len(serialized) - 5:] if len(serialized) < 5 else [])

        # if we didn't get any names, then proceed to decode each field, verify that the
        # lengths match, and then decode them into a list of strings to return.
        if not names:
            results = cls.decode_bytes(fields or b'')
            assert(all(length == len(encoded) for length, encoded in results))
            return [encoded.decode('utf-8') for _, encoded in results]

        # otherwise re-encode the names we were given back into the type after clamping them.
        [items] = names
        if isinstance(items, internal.types.ordered):
            encoded = (bytes(item) if isinstance(item, (bytes, bytearray)) else item.encode('utf-8') for item in items)
            return cls.get(library, type, cls.encode_bytes([chunk[:0xfe] for chunk in encoded]), cmt or fieldcmts)

        elif isinstance(items, (internal.types.string, bytes, bytearray)):
            encoded = bytes(items) if isinstance(items, (bytes, bytearray)) else items.encode('utf-8')
            return cls.get(library, type, encoded, cmt or fieldcmts)
        raise internal.exceptions.InvalidTypeOrValueError(u"{:s}.names({!s}, {!r}) : Unable to set the names for the given type information using an unsupported type ({!s}).".format('.'.join([__name__, cls.__name__]), internal.utils.string.escape(description, '"'), items, items.__class__.__name__))

    @classmethod
    def comments(cls, type, *comments):
        '''Return the comments for the fields within the given `type` or return a new `type` if any `comments` are given.'''
        library, serialized, description = type.get_til(), type.serialize(), "{!s}".format(type)
        type, fields, cmt, fieldcmts, sclass = itertools.chain(serialized, [b'\x01', b'', b'', b'', getattr(idaapi, 'sc_unk', 0)][len(serialized) - 5:] if len(serialized) < 5 else [])

        # if we didn't get any comments, then proceed to decode each field, verify that the
        # lengths match, and then decode them into a list of strings to return.
        if not comments:
            results = cls.decode_bytes(cmt or fieldcmts or b'')
            assert(all(length == len(encoded) for length, encoded in results))
            return [encoded.decode('utf-8') for _, encoded in results]

        # otherwise re-encode the comments we were given back into the type after clamping them.
        [items] = comments
        if isinstance(items, internal.types.ordered):
            encoded = (bytes(item) if isinstance(item, (bytes, bytearray)) else item.encode('utf-8') for item in items)
            return cls.get(library, type, fields, cls.encode_bytes([chunk[:0xfe] for chunk in encoded]))

        elif isinstance(items, (internal.types.string, bytes, bytearray)):
            encoded = bytes(items) if isinstance(items, (bytes, bytearray)) else items.encode('utf-8')
            return cls.get(library, type, fields, encoded)
        raise internal.exceptions.InvalidTypeOrValueError(u"{:s}.comments({!s}, {!r}) : Unable to set the comments for the given type information using an unsupported type ({!s}).".format('.'.join([__name__, cls.__name__]), internal.utils.string.escape(description, '"'), items, items.__class__.__name__))

    @classmethod
    def compare(cls, type, other, *flags):
        '''Compares the specified `type` to `other` for castability using the given `flags`.'''
        if idaapi.__version__ < 6.8:
            til = cls.library(type)
            return idaapi.is_castable2(til, type, other)
        [tcflags] = flags if flags else [idaapi.TCMP_AUTOCAST]
        return type.compare_with(other, tcflags)

    @classmethod
    def equals(cls, type, other):
        '''Return whether the specified `type` is essentially equivalent to the `other` type.'''
        if idaapi.__version__ < 6.8:
            til = cls.library(type)
            return idaapi.equal_types(til, type, other)
        return type.equals_to(other)

    @classmethod
    def same(cls, type, other):
        '''Return whether the specified `type` is the exact same as the `other` type.'''
        if idaapi.__version__ < 6.8:
            til = cls.library(type)
            return idaapi.equal_types(til, type, other)

        elif type.empty() or other.empty():
            return type.empty() == other.empty()

        return type.serialize() == other.serialize()

    @classmethod
    def resolve(cls, type):
        '''Return the type for the target that is being referenced by the specified nested pointer `type`.'''
        tinfo = type

        # If there are no details, then technically we're already there.
        if not tinfo.has_details():
            return cls.copy(tinfo)

        # If our type is a pointer, then we need to extract the pointer details
        # from it so that we can dereference the type and recurse into ourselves.
        elif tinfo.is_ptr():
            pi = idaapi.ptr_type_data_t()
            if not tinfo.get_ptr_details(pi):
                raise internal.exceptions.DisassemblerError(u"{:s}.resolve({!r}) : Unable to get the pointer type data from the provided type information ({!r}).".format('.'.join([__name__, cls.__name__]), "{!s}".format(type), "{!s}".format(tinfo)))
            return cls.resolve(pi.obj_type)

        # Last thing to do is to concretize the type prior to returning it.
        til, resolved = cls.library(tinfo), cls.copy(tinfo)
        res = idaapi.replace_ordinal_typerefs(til, resolved) if hasattr(idaapi, 'replace_ordinal_typerefs') else 0
        if res < 0:
            logging.debug(u"{:s}.resolve({!r}) : Ignoring error {:d} while trying to concretize the provided type \"{:s}\".".format('.'.join([__name__, cls.__name__]), "{!s}".format(type), internal.utils.string.escape("{!s}".format(tinfo), '"')))
        return tinfo if res < 0 else resolved

    @classmethod
    def array(cls, type):
        '''Return a tuple containing the element type and length of the array specified by `type`.'''
        ai = idaapi.array_type_data_t()

        # If there's no details, then this is definitely not an array.
        if not type.has_details():
            raise internal.exceptions.MissingTypeOrAttribute(u"{:s}.array({!r}) : The specified type information ({!r}) does not contain any details.".format('.'.join([__name__, cls.__name__]), "{!s}".format(type), "{!s}".format(type)))

        # If it's not an array, then this is definitely not an array.
        elif not type.is_array():
            raise internal.exceptions.InvalidTypeOrValueError(u"{:s}.array({!r}) : The specified type information ({!r}) is not an array.".format('.'.join([__name__, cls.__name__]), "{!s}".format(type), "{!s}".format(type)))

        # If there's no array details, then this is definitely not an array.
        elif not type.get_array_details(ai):
            raise internal.exceptions.DisassemblerError(u"{:s}.array({!r}) : Unable to get the array type data from the specified type information ({!r}).".format('.'.join([__name__, cls.__name__]), "{!s}".format(type), "{!s}".format(type)))

        # If we got here, then this definitely is an array and we only
        # need to concretize the element type prior to returning it.
        til, element = cls.library(ai.elem_type), cls.copy(ai.elem_type)
        res = idaapi.replace_ordinal_typerefs(til, element) if hasattr(idaapi, 'replace_ordinal_typerefs') else 0
        if res < 0:
            logging.debug(u"{:s}.array({!r}) : Ignoring error {:d} while trying to concretize the element type \"{:s}\".".format('.'.join([__name__, cls.__name__]), "{!s}".format(type), internal.utils.string.escape("{!s}".format(ai.elem_type), '"')))
        return ai.elem_type if res < 0 else element, ai.nelems

    @classmethod
    def structure(cls, type):
        '''Return the structure or union that is referenced by the specified array or pointer `type`.'''
        tinfo = type

        # If there's no details, then this is definitely not an array or a structure.
        if not tinfo.has_details():
            raise internal.exceptions.MissingTypeOrAttribute(u"{:s}.structure({!r}) : The specified type information ({!r}) does not contain any details.".format('.'.join([__name__, cls.__name__]), internal.utils.string.escape("{!s}".format(tinfo), '"'), "{!s}".format(tinfo)))

        # If our type is a pointer, then we need to use the pointer details to recurse.
        elif tinfo.is_ptr():
            pi = idaapi.ptr_type_data_t()
            if not tinfo.get_ptr_details(pi):
                raise internal.exceptions.DisassemblerError(u"{:s}.structure({!r}) : Unable to get the pointer type data from the provided type information ({!r}).".format('.'.join([__name__, cls.__name__]), "{!s}".format(tinfo), "{!s}".format(tinfo)))
            return cls.structure(pi.obj_type)

        # If it's an array, then we need to extract the array element and then recurse.
        elif tinfo.is_array():
            ai = idaapi.array_type_data_t()
            if not tinfo.get_array_details(ai):
                raise internal.exceptions.DisassemblerError(u"{:s}.structure({!r}) : Unable to get the array type data from the provided type information ({!r}).".format('.'.join([__name__, cls.__name__]), "{!s}".format(tinfo), "{!s}".format(tinfo)))
            return cls.structure(ai.elem_type)

        # If it's still not a structure, then we have something else.
        elif not any([tinfo.is_struct(), tinfo.is_union()]):
            raise internal.exceptions.InvalidTypeOrValueError(u"{:s}.structure({!r}) : Unable to determine the structure from the provided type information ({!r}).".format('.'.join([__name__, cls.__name__]), "{!s}".format(tinfo), "{!s}".format(tinfo)))

        # That's it and we only need to resolve its ordinals before returning it.
        til, resolved = cls.library(tinfo), cls.copy(tinfo)
        res = idaapi.replace_ordinal_typerefs(til, resolved) if hasattr(idaapi, 'replace_ordinal_typerefs') else 0
        if res < 0:
            raise internal.exceptions.InvalidTypeOrValueError(u"{:s}.structure({!r}) : Ignoring error {:d} while trying to concretize the structuire type \"{:s}\".".format('.'.join([__name__, cls.__name__]), "{!s}".format(tinfo), internal.utils.string.escape("{!s}".format(tinfo), '"')))
        return tinfo if res < 0 else resolved

    @classmethod
    def members(cls, type):
        '''Yield a tuple for each member in the structure, union, or array that is specified by `type`.'''
        if not type.has_details():
            raise internal.exceptions.MissingTypeOrAttribute(u"{:s}.members({!r}) : The specified type information ({!r}) does not contain any details.".format('.'.join([__name__, cls.__name__]), "{!s}".format(type), "{!s}".format(type)))

        # We only support udt and array types with this function.
        elif not any([type.is_udt(), type.is_array(), type.is_enum()]):
            raise internal.exceptions.InvalidTypeOrValueError(u"{:s}.members({!r}) : The specified type information ({!r}) does not contain any members.".format('.'.join([__name__, cls.__name__]), "{!s}".format(type), "{!s}".format(type)))

        # If our type is an array, then our job is fairly easy here.
        if type.is_array():
            ai = idaapi.array_type_data_t()
            if not type.get_array_details(ai):
                raise internal.exceptions.DisassemblerError(u"{:s}.members({!r}) : Unable to get the array type data from the specified type information ({!r}).".format('.'.join([__name__, cls.__name__]), "{!s}".format(type), "{!s}".format(type)))

            # Get the relevant attributes for the array that we'll use in our iterator.
            base, element, esize = ai.base, ai.elem_type, ai.elem_type.get_size()
            size, unpadded, count = type.get_size(), type.get_unpadded_size(), ai.nelems

            effective_alignment, declared_alignment, pack_alignment = 0, pow(2, element.get_declalign()), pow(2, 0)

            # Now we can create our iterator that gets returned to the caller.
            index_offset = ((base + index, index * element.get_size()) for index in builtins.range(count))
            copied = [(index, 8 * offset, 8 * element.get_size(), cls.copy(element), declared_alignment) for index, offset in index_offset]
            iterable = (item for item in copied)

        # If our type is an enumeration (or enumeration bitmask), then we have
        # to do all the work to calculate the member information for the enum.
        elif type.is_enum():
            etd, tabits = idaapi.enum_type_data_t(), [idaapi.TAENUM_64BIT, idaapi.TAENUM_UNSIGNED, idaapi.TAENUM_SIGNED]
            if not type.get_enum_details(etd):
                raise internal.exceptions.DisassemblerError(u"{:s}.members({!r}) : Unable to get the enumeration type data from the specified type information ({!r}).".format('.'.join([__name__, cls.__name__]), "{!s}".format(type), "{!s}".format(type)))

            # start by taking our group sizes and aggregating them into a list
            # of indices and eventually the boundaries for our bit masks.
            group_sizes = [etd.group_sizes[index] for index in builtins.range(etd.group_sizes.size())]
            group_indices = functools.reduce(lambda gsizes, gsize: gsizes + [gsize + gsizes[-1]], group_sizes, [0])
            group_bounds = [(gindex, gsize) for gindex, gsize in zip(group_indices, group_sizes + [0])]

            # then we grab any information about the enumeration that we can and
            # create an integer type for our enumeration that we'll use later.
            size_exponent, out_format = etd.bte & idaapi.BTE_SIZE_MASK, etd.bte & idaapi.BTE_OUT_MASK
            integer_size, tah = pow(2, size_exponent), {bit : etd.taenum_bits & bit for bit in tabits}

            integer_types = {0: idaapi.BT_VOID | idaapi.BTMT_SIZE0, 1: idaapi.BT_INT8, 2: idaapi.BT_INT16, 4: idaapi.BT_INT32, 8: idaapi.BT_INT64, 16: idaapi.BT_INT128}
            integer_type = idaapi.tinfo_t(integer_types[integer_size])

            iterable = (etd[index] for index in builtins.range(etd.size()))
            members = [(internal.utils.string.of(edm.name), edm.value, internal.utils.string.of(edm.cmt)) for edm in iterable]

            # if the enumeration is a bitmask, then we need to figure out its
            # individual sizes so that we can create a bitfield for them.
            if len(group_bounds) > 1:
                group_bits = {}

                # iterate through all of the indices (other than the length at
                # the end), and figure out the number of bits for each member.
                # we calculate the total number of bits rather than the bits
                # that are set to ensure that the size of the type is correct.
                group_offsets = {}
                for index in group_indices[:-1]:
                    _, value, _ = members[index]
                    maximum = pow(2, value.bit_length()) - 1

                    group_offsets[index] = lsb = (+value & -value).bit_length() - 1
                    mask, _ = divmod(maximum, pow(2, lsb))
                    group_bits[index] = width = mask.bit_length()

                # now we have the number of bits for each group, and can use
                # them to create a bitfield for each one.
                group_types = {}
                for index, width in group_bits.items():
                    btd = idaapi.bitfield_type_data_t()
                    btd.nbytes, btd.width = integer_size, width

                    # try and create the bitfield. if we failed at creating it,
                    # then we fall back to the integer type for the enumeration.
                    group_type = idaapi.tinfo_t()
                    if not group_type.create_bitfield(btd):
                        group_type = integer_type
                    group_types[index] = cls.copy(group_type)

                # all that's left is to update our member types with the indices
                # for the types so that we can use them in our member iterator.
                iterable = (zip([index] * size, builtins.range(index, index + size)) for index, size in group_bounds)
                chained = [pair for pair in itertools.chain(*iterable)]
                member_types = {index : cls.copy(group_types[gindex]) for gindex, index in chained}
                member_offsets = {index : group_offsets[gindex] for gindex, index in chained}
                member_sizes = {index : group_bits[gindex] for gindex, index in chained}

            # if the enumeration is not a bitmask, meaning its group_indices are
            # empty, then we can just create a type for its integer size.
            else:
                member_types = {index: integer_type for index, _ in enumerate(members)}
                member_offsets = {index : 0 for index, _ in enumerate(members)}
                member_sizes = {index : integer_size for index, _ in enumerate(members)}

            # now we can return our iterator for the members and their types. if
            # there are any bitmasks, then we just skip over them.
            member_information = ((member_offsets[index], member_sizes[index], member_types[index]) for index, _ in enumerate(members))
            copied = [(mname, moffset, msize, cls.copy(mtype), 1) for (mname, mvalue, mcomment), (moffset, msize, mtype) in zip(members, member_information)]
            iterable = (item for item in copied)

        # Otherwise we need to extract the members differently.
        elif type.is_udt():
            utd = idaapi.udt_type_data_t()
            if not type.get_udt_details(utd):
                raise internal.exceptions.DisassemblerError(u"{:s}.members({!r}) : Unable to get the udt type data from the specified type information ({!r}).".format('.'.join([__name__, cls.__name__]), "{!s}".format(type), "{!s}".format(type)))

            # Grab literally all the fields just in case we might need them.
            effective_alignment, declared_alignment, pack_alignment = utd.effalign, pow(2, utd.sda - 1) if utd.sda else 0, pow(2, utd.pack)
            size, unpadded, count = utd.total_size, utd.unpadded_size, utd.size()

            # Now we can create an iterator that returns information about each member.
            index_member = ((index, utd[index]) for index in builtins.range(count))
            copied = [(internal.utils.string.of(member.name), member.offset, member.size, cls.copy(member.type), pow(2, member.fda)) for index, member in index_member]
            iterable = (item for item in copied)

        # Any other type is pretty much unknown and so we just bail the search.
        else:
            raise internal.exceptions.InvalidTypeOrValueError(u"{:s}.members({!r}) : Unable to access the type data for an unsupported type ({!r}).".format('.'.join([__name__, cls.__name__]), "{!s}".format(type), "{!s}".format(type)))

        # Now we need to process our iterable to concretize each type being returned.
        # To do this, we first make an iterable with a copy of the original that we'll
        # attempt to resolve. If we didn't succeed, then we fall back to the original.
        Fstrip_ordinals = idaapi.replace_ordinal_typerefs if hasattr(idaapi, 'replace_ordinal_typerefs') else lambda library, ti: 0
        iterable = ((mname, moffset, msize, cls.library(mtype), mtype, cls.copy(mtype), malign) for mname, moffset, msize, mtype, malign in iterable)
        resolved = ((mname, moffset, msize, moldtype if Fstrip_ordinals(til, mnewtype) < 0 else mnewtype, malign) for mname, moffset, msize, til, moldtype, mnewtype, malign in iterable)
        return [(mname, moffset, msize, mtype, malign) for mname, moffset, msize, mtype, malign in resolved]

    @classmethod
    def parse(cls, library, string, flags=0):
        '''Use the given `flags` to parse the given `string` into an ``idaapi.tinfo_t`` for the specified type `library` and return it.'''
        ti, flag, til = idaapi.tinfo_t(), flags | idaapi.PT_SIL, cls.library() if library is None else library

        # Now we ';'-terminate the type in order for the disassembler to understand it.
        terminated = string if string.rstrip().endswith(';') else "{:s};".format(string)
        stripped = terminated.strip('; ')

        # If the terminated string is 'void', then manually create the void type
        # since the disassembler refuses to parse 'void' into a type for us.
        if stripped in {'void'}:
            BTF_VOID = idaapi.BTF_VOID if hasattr(idaapi, 'BTF_VOID') else getattr(idaapi, 'BT_VOID', 1) | getattr(idaapi, 'BTMT_SIZE0', 0)
            return cls.get(til, bytearray([BTF_VOID]))

        # XXX: If the stripped name is _BOOL8, then the type is really _BOOL2 on 64-bit.
        elif stripped in {64: {'_BOOL8'}}.get(database.bits(), {}):
            BOOL_16o64 = getattr(idaapi, 'BT_BOOL', 8) | getattr(idaapi, 'BTMT_SIZE48', 0x20)
            return cls.get(til, bytearray([BOOL_16o64]))

        # For some reason the disassembler does not like to parse pointers/arrays to
        # unnamed unions that are prefixed with "union"...So, we have to strip it.
        elif not flags & idaapi.PT_VAR and stripped.startswith(('union ', 'const union ')) and stripped.endswith(('*', '*const', '&', '&const', ']')):
            for_split_twice = ' ' + terminated.lstrip() if stripped.startswith('union ') else terminated.lstrip()
            _, _, terminated = for_split_twice.split(' ', 2)

        # Ask the disassembler to parse this into a tinfo_t for us. We default to the
        # silent flag so that we're responsible for handling it if there's an error.
        if idaapi.__version__ < 6.9:
            ok, name = idaapi.parse_decl2(til, internal.utils.string.to(terminated), None, ti, flag), None
        elif idaapi.__version__ < 7.0:
            ok, name = idaapi.parse_decl2(til, internal.utils.string.to(terminated), ti, flag), None
        else:
            name = idaapi.parse_decl(ti, til, internal.utils.string.to(terminated), flag)
            ok = name is not None

        # If we were unable to parse the string we were given, then return nothing.
        if not ok:
            return

        # Now we just need to strip out of the ordinals of the type we return.
        old, new = ti, cls.copy(ti)
        res = idaapi.replace_ordinal_typerefs(til, new) if hasattr(idaapi, 'replace_ordinal_typerefs') else 0
        ti = old if res < 0 else new

        # If we were given the idaapi.PT_VAR flag, then we return the parsed name too.
        string = internal.utils.string.of(name)
        return (string or u'', ti) if flag & idaapi.PT_VAR else ti

    @classmethod
    def get_numbered_type(cls, library, ordinal):
        '''Return the serialized type information for the given `ordinal` from the specified type `library`.'''
        til = library if library else cls.library()

        # attempt to use the regular api.. this should generally work.
        try:
            return idaapi.get_numbered_type(til, ordinal)

        # if we encountered a UnicodeDecodeError as per idapython/src#57,
        # then we'll just use ctypes to perform a workaround.
        except (RuntimeError, UnicodeDecodeError):
            import ida

        # first the parameters for get_numbered_type.
        til_t, type_t, sclass_t, p_list = ctypes.POINTER(ctypes.c_void_p), ctypes.c_char_p, ctypes.c_long, ctypes.c_char_p
        if not getattr(ida.get_numbered_type, 'argtypes', None):
            ida.get_numbered_type.restype = ctypes.c_bool
            ida.get_numbered_type.argtypes = til_t, ctypes.c_uint32, ctypes.POINTER(type_t), ctypes.POINTER(p_list), ctypes.POINTER(ctypes.c_char_p), ctypes.POINTER(p_list), ctypes.POINTER(sclass_t)

        # then the parameters for getting the current type library.
        if not getattr(ida.get_idati, 'argtypes', None):
            ida.get_idati.restype = til_t
            ida.get_idati.argtypes = ()

        # then the parameters for managing the scope of a type library
        if not getattr(ida.new_til, 'argtypes', None):
            ida.new_til.restype = til_t
            ida.new_til.argtypes = ctypes.c_char_p, ctypes.c_char_p

        if not getattr(ida.free_til, 'argtypes', None):
            ida.free_til.restype = ctypes.c_bool    # actually void
            ida.free_til.argtypes = til_t,

        # first we need a type library of some sort. we can't actually use the library we were given
        # as a parameter, so we'll need to try and grab the default one or create a temporary one.
        name, desc = (internal.utils.string.of(library.name), internal.utils.string.of(library.desc)) if library else (u'', u'Temporary type definitions')
        owned, result = False, None
        try:
            res = ida.get_idati()
            owned, til = (True, ida.new_til(name.encode('utf-8'), desc.encode('utf-8'))) if not res else (False, res)

            # now we'll allocate space for the variables that will be written to.
            type, fields, cmt, fieldcmts, sclass = type_t(), p_list(), ctypes.c_char_p(), p_list(), sclass_t()

            # hopefully we can now use the api safely and pack everything we got into a tuple.
            res = ()
            if ida.get_numbered_type(til, ordinal, ctypes.pointer(type), ctypes.pointer(fields), ctypes.pointer(cmt), ctypes.pointer(fieldcmts), ctypes.pointer(sclass)):
                res = (item.value if item else None for item in [type, fields, cmt, fieldcmts, sclass])

            # ...and then pack everything we got into a tuple.
            result = tuple(res) if res else None
        finally:
            owned and til and ida.free_til(til)
        return result

    @classmethod
    def format_type_error(cls, code):
        '''Return the specified error `code` as a tuple composed of the error name and its description.'''
        descriptions, names = {}, {getattr(idaapi, attribute) : attribute for attribute in dir(idaapi) if attribute.startswith('TERR_')}
        descriptions[idaapi.TERR_OK] = 'ok'
        descriptions[idaapi.TERR_SAVE] = 'failed to save'
        descriptions[idaapi.TERR_SERIALIZE] = 'failed to serialize'
        descriptions[getattr(idaapi, 'TERR_TOOLONGNAME', getattr(idaapi, 'TERR_WRONGNAME', -3))] = 'name is too long' if hasattr(idaapi, 'TERR_TOOLONGNAME') else 'name is not acceptable'
        descriptions[getattr(idaapi, 'TERR_BADSYNC', -4)] = 'failed to synchronize with IDB'
        return names.get(code, ''), descriptions.get(code, '')

    @classmethod
    def set_numbered_type(cls, library, ordinal, name, type, *flags):
        '''Set the type at the specified `ordinal` for a type `library` using the given `name` and serialized `type` information.'''
        description = "{!s}".format(type) if isinstance(type, idaapi.tinfo_t) else "{!r}".format(type)
        serialized, til = type.serialize() if isinstance(type, idaapi.tinfo_t) else type, cls.library(type) if library is None and isinstance(type, idaapi.tinfo_t) else library
        type, fields, cmt, fieldcmts, sclass = itertools.chain(serialized, [b'\x01', b'', b'', b'', getattr(idaapi, 'sc_unk', 0)][len(serialized) - 5:] if len(serialized) < 5 else [])

        # now we can allocate a slot for the ordinal within the type library if necessary.
        index = ordinal if ordinal and ordinal > 0 else idaapi.alloc_type_ordinals(til, 1)
        if index < 1:
            raise internal.exceptions.DisassemblerError(u"{:s}.set_numbered_type({!s}, {!s}, {!r}, {!r}{:s}) : Unable to allocate an ordinal within the specified type library.".format('.'.join([__name__, cls.__name__]), library, ordinal, name, description, u", {!s}".format(*flags) if flags else ''))

        # set the default flags that we're going to use when using set_numbered_type.
        [flag] = flags if flags else [idaapi.NTF_CHKSYNC | idaapi.NTF_TYPE]
        flag |= idaapi.NTF_REPLACE if ordinal > 0 else 0

        # last thing we need to do is correct the name we were given to a valid one
        # since IDA wants these to follow the format (character set) for a general C
        # identifier. so we'll simply do the first character, then finish the rest.
        iterable = (item for item in name)
        item = builtins.next(iterable, '_')
        identifier = item if idaapi.is_valid_typename(internal.utils.string.to(item)) else '_'
        identifier+= str().join(item if idaapi.is_valid_typename(identifier + internal.utils.string.to(item)) else '_' for item in iterable)

        # we can now assign the serialized data that we got, making sure that
        # the comments are properly being passed as bytes before checking for error.
        result = idaapi.set_numbered_type(library, index, flag, internal.utils.string.to(identifier), type, fields, cmt.decode('latin1') if isinstance(cmt, internal.types.bytes) else cmt, fieldcmts if isinstance(fieldcmts, internal.types.bytes) else fieldcmts.encode('latin1'), sclass)
        if result == idaapi.TERR_OK:
            return index

        # if we got an error, then we need to delete the ordinal we just added
        # and then we can just raise an exception for the user to deal with.
        if ordinal <= idaapi.TERR_OK and not idaapi.del_numbered_type(library, ordinal):
            logging.fatal(u"{:s}.set_numbered_type({!s}, {!s}, {!r}, {!r}{:s}) : Unable to delete the recently added ordinal ({:d}) from the specified type library.".format('.'.join([__name__, cls.__name__]), library, ordinal, name, description, u", {!s}".format(*flags) if flags else '', index))

        # now we can check the error code and log the error before returning it.
        error_name, error_description = cls.format_type_error(result)
        if result == getattr(idaapi, 'TERR_WRONGNAME', getattr(idaapi, 'TERR_TOOLONGNAME', -3)):
            logging.info(u"{:s}.set_numbered_type({!s}, {!s}, {!r}, {!r}{:s}) : Unable to add the type information to the type library at the allocated ordinal ({:d}) with the given name ({!r}) due to error {:s}.".format('.'.join([__name__, cls.__name__]), library, ordinal, name, description, u", {!s}".format(*flags) if flags else '', index, identifier, "{:s}({:d})".format(error_name, result) if result else "code ({:d})".format(result)))
        else:
            logging.info(u"{:s}.set_numbered_type({!s}, {!s}, {!r}, {!r}{:s}) : Unable to add the type information to the type library at the allocated ordinal ({:d}) due to error {:s}.".format('.'.join([__name__, cls.__name__]), library, ordinal, name, description, u", {!s}".format(*flags) if flags else '', ordinal, "{:s}({:d})".format(error_name, result) if result else "code ({:d})".format(result)))

        # our result should be less than 0, so we bail here as a sanity-check.
        if result < 0:
            return result

        error_name, error_description = cls.format_type_error(result)
        raise internal.exceptions.AssertionError(u"{:s}.set_numbered_type({!s}, {!s}, {!r}, {!r}{:s}) : Received an unexpected error {:s} that should have been less than {:d}.".format('.'.join([__name__, cls.__name__]), library, ordinal, name, description, u", {!s}".format(*flags) if flags else '', "{:s}({:d})".format(error_name, result) if error_name else "code ({:d})".format(result), 0))

    @classmethod
    def get_named_type(cls, library, name, flags):
        '''Return the serialized type information for the type with the given `name` and `flags` from the specified type `library`.'''
        til = library if library else cls.library()

        # attempt to use the regular api.. this should generally work.
        try:
            return idaapi.get_named_type(til, internal.utils.string.to(name), flags)

        # if we encountered a UnicodeDecodeError as per idapython/src#57,
        # then we fall back to using ctypes to perform the workaround.
        except (RuntimeError, UnicodeDecodeError):
            import ida

        # create the parameters and assign them to get_named_type.
        til_t, type_t, sclass_t, p_list, value_t = ctypes.POINTER(ctypes.c_void_p), ctypes.c_char_p, ctypes.c_long, ctypes.c_char_p, ctypes.c_uint32
        if not getattr(ida.get_named_type, 'argtypes', None):
            ida.get_named_type.restype = ctypes.c_int
            ida.get_named_type.argtypes = til_t, ctypes.c_char_p, ctypes.c_int, ctypes.POINTER(type_t), ctypes.POINTER(p_list), ctypes.POINTER(ctypes.c_char_p), ctypes.POINTER(p_list), ctypes.POINTER(sclass_t), ctypes.POINTER(value_t)

        # we need to get the current type library, so assign those too.
        if not getattr(ida.get_idati, 'argtypes', None):
            ida.get_idati.restype = til_t
            ida.get_idati.argtypes = ()

        if not getattr(ida.new_til, 'argtypes', None):
            ida.new_til.restype = til_t
            ida.new_til.argtypes = ctypes.c_char_p, ctypes.c_char_p

        if not getattr(ida.free_til, 'argtypes', None):
            ida.free_til.restype = ctypes.c_bool    # actually void
            ida.free_til.argtypes = til_t,

        # to start out, we need a type library of the right type since the one
        # from idapython is a swiggy type. we snag the default type library here.
        libname, libdesc = (internal.utils.string.of(library.name), internal.utils.string.of(library.desc)) if library else (u'', u'Temporary type definitions')
        owned, result = False, None

        try:
            res, encoded_name = ida.get_idati(), name if isinstance(name, bytes) else name.encode('utf-8')
            owned, til = (True, ida.new_til(libname.encode('utf-8'), libdesc.encode('utf-8'))) if not res else (False, res)

            # similar to get_numbered_type, we need to allocate space for
            # the variables that will be written to when we call the api.
            type, fields, cmt, fieldcmts, sclass, value = type_t(), p_list(), ctypes.c_char_p(), p_list(), sclass_t(), value_t()
            retcode = ida.get_named_type(til, encoded_name, flags, ctypes.pointer(type), ctypes.pointer(fields), ctypes.pointer(cmt), ctypes.pointer(fieldcmts), ctypes.pointer(sclass), ctypes.pointer(value))

            # if the retcode from get_named_type was 0, idapython returns None.
            if retcode == 0:
                return None

            # now we need to snag all the referenced values that were written to.
            referenced_values = (item.value if item else None for item in [type, fields, cmt, fieldcmts, sclass, value])

            # then we pack the return code with the referenced values into a tuple.
            result = tuple(itertools.chain([retcode], referenced_values))

        finally:
            owned and til and ida.free_til(til)
        return result

    @classmethod
    def function_spoiled(cls, info):
        '''Return a list of registers spoiled by the function prototype specified in `info`.'''
        tinfo = info
        while tinfo.is_ptr():
            tinfo = tinfo.get_pointed_object()

        # Spoiled registers only apply to a function prototype, so bail if it isn't.
        if not any([tinfo.is_func(), tinfo.is_funcptr()]):
            raise internal.exceptions.InvalidTypeOrValueError(u"{:s}.function_spoiled({!r}) : The resolved type information \"{:s}\" is not a function and does not contain any arguments.".format('.'.join([__name__, cls.__name__]), "{!s}".format(info), internal.utils.string.escape("{!s}".format(tinfo), '"')))

        # If we're unable to get details from the type, then we need to abort.
        elif not tinfo.has_details():
            raise internal.exceptions.MissingTypeOrAttribute(u"{:s}.function_spoiled({!r}) : The resolved type information \"{:s}\" does not contain any details.".format('.'.join([__name__, cls.__name__]), "{!s}".format(info), internal.utils.string.escape("{!s}".format(tinfo), '"')))

        # Extract the function details from the type so that we can check it out.
        ftd = idaapi.func_type_data_t()
        ok = tinfo.get_func_details(ftd) or tinfo.get_func_details(ftd, idaapi.GTD_NO_ARGLOCS)
        if not ok:
            raise internal.exceptions.DisassemblerError(u"{:s}.function_spoiled({!r}) : Unable to retrieve the details from the specified type information \"{:s}\".".format('.'.join([__name__, cls.__name__]), "{!s}".format(info), internal.utils.string.escape("{!s}".format(tinfo), '"')))

        # Now we just need to access the reginfovec_t stored in ftd.spoiled. Each
        # element of this array is a reginfo_t which we can easily convert to a reg.
        result = []
        for index in builtins.range(ftd.spoiled.size()):
            reginfo = ftd.spoiled[index]
            ridx, rsize = reginfo.reg, reginfo.size

            # If the register doesn't exist, we just skip over it.
            if not architecture.has(ridx):
                logging.warning(u"{:s}.function_spoiled({!r}) : Unable to locate the spoiled register at the current index ({:d}) due to the register index being unknown ({:d}).".format('.'.join([__name__, cls.__name__]), "{!s}".format(info), index, ridx))
                continue

            # If we couldn't find a register of the exact size,
            # then just use a regular register and issue a warning.
            try:
                reg = architecture.by(ridx, rsize)

            except IndexError:
                logging.warning(u"{:s}.function_spoiled({!r}) : The spoiled register at the current index ({:d}) has an unsupported size ({:d}).".format('.'.join([__name__, cls.__name__]), "{!s}".format(type), index, rsize))
                reg = architecture.by(ridx)

            # Now we can add it and try the next one.
            result.append(reg)
        return result

    @classmethod
    def update_function_spoiled(cls, info, registers):
        '''Update the list of spoiled registers in the function prototype `info` with the specified `registers`.'''
        tinfo, ftd = cls.copy(info), idaapi.func_type_data_t()

        # Spoiled registers only apply to a function prototype, so bail if it isn't.
        if not tinfo.is_func():
            raise internal.exceptions.InvalidTypeOrValueError(u"{:s}.update_function_spoiled({!r}, {!r}) : The resolved type information \"{:s}\" is not a function and does not contain any arguments.".format('.'.join([__name__, cls.__name__]), "{!s}".format(info), registers, internal.utils.string.escape("{!s}".format(tinfo), '"')))

        # If we're unable to get details from the type, then we need to abort.
        elif not tinfo.has_details():
            raise internal.exceptions.MissingTypeOrAttribute(u"{:s}.update_function_spoiled({!r}, {!r}) : The resolved type information \"{:s}\" does not contain any details.".format('.'.join([__name__, cls.__name__]), "{!s}".format(info), registers, internal.utils.string.escape("{!s}".format(tinfo), '"')))

        # Extract the function details from the type so that we can modify it.
        ok = tinfo.get_func_details(ftd) or tinfo.get_func_details(ftd, idaapi.GTD_NO_ARGLOCS)
        if not ok:
            raise internal.exceptions.DisassemblerError(u"{:s}.update_function_spoiled({!r}, {!r}) : Unable to retrieve the details from the specified type information \"{:s}\".".format('.'.join([__name__, cls.__name__]), "{!s}".format(info), registers, internal.utils.string.escape("{!s}".format(tinfo), '"')))

        # Before we do anything, we need to convert the list of registers we were
        # given into a register index and a size. We support register_t (both),
        # register names, and tuples of the register index and the size.
        reginfo = []
        for reg in (registers or []):
            identifier, _ = reg if isinstance(reg, tuple) else (reg, reg)
            if not architecture.has(identifier):
                logging.warning(u"{:s}.update_function_spoiled({!r}, {!r}) : Skipping unknown register ({!r}) being added to the list of spoiled registers.".format('.'.join([__name__, cls.__name__]), "{!s}".format(info), registers, reg))
                continue
            realreg = architecture.by(reg)
            reginfo.append((realreg.id, realreg.size))

        # Now we just need to resize the reginfovec_t and then
        # we can update it with our list of register entries.
        original, _, capacity = ftd.spoiled.capacity(), ftd.spoiled.resize(len(reginfo)), ftd.spoiled.size()
        if capacity != len(reginfo):
            raise internal.exceptions.DisassemblerError(u"{:s}.update_function_spoiled({!r}, {!r}) : Unable to modify the capacity ({:d}) of the `{:s}` ({:d}) from the function type in order to reserve space for {:d} register{:s}.".format('.'.join([__name__, cls.__name__]), "{!s}".format(info), registers, original, internal.utils.pycompat.fullname(ftd.spoiled.__class__), capacity, len(reginfo), '' if len(reginfo) == 1 else 's'))

        for index, (ridx, rsize) in enumerate(reginfo):
            ftd.spoiled[index].reg = ridx
            ftd.spoiled[index].size = rsize
        ftd.flags = (ftd.flags & ~idaapi.FTI_SPOILED) | (0 if registers is None else idaapi.FTI_SPOILED)

        # Now we just need re-create the function using our updated function details.
        newtype = cls.copy(info)
        if not newtype.create_func(ftd):
            raise internal.exceptions.DisassemblerError(u"{:s}.update_function_spoiled({!r}, {!r}) : Unable to create a function type with the updated details ({:d} spoiled register{:s}).".format('.'.join([__name__, cls.__name__]), "{!s}".format(info), registers, len(reginfo), '' if len(reginfo) == 1 else 's'))
        return newtype

    @classmethod
    def function(cls, type):
        '''Return a list containing a tuple for the return type and each argument for the function specified by `type`.'''
        tinfo = type
        while tinfo.is_ptr():
            tinfo = tinfo.get_pointed_object()

        # Ensure that we were able to get a function type from our parameter.
        if not any([tinfo.is_func(), tinfo.is_funcptr()]):
            raise internal.exceptions.InvalidTypeOrValueError(u"{:s}.function({!r}) : The resolved type information \"{:s}\" is not a function and does not contain any arguments.".format('.'.join([__name__, cls.__name__]), "{!s}".format(type), internal.utils.string.escape("{!s}".format(tinfo), '"')))

        # Make sure that the type has some details that we can extract.
        elif not tinfo.has_details():
            raise internal.exceptions.MissingTypeOrAttribute(u"{:s}.function({!r}) : The resolved type information \"{:s}\" does not contain any details.".format('.'.join([__name__, cls.__name__]), "{!s}".format(type), internal.utils.string.escape("{!s}".format(tinfo), '"')))

        # Before doing anything, we need to concretize the ordinals out of the type..
        til, old, new = cls.library(tinfo), tinfo, cls.copy(tinfo)
        res = idaapi.replace_ordinal_typerefs(til, new) if hasattr(idaapi, 'replace_ordinal_typerefs') else 0
        if res < 0:
            logging.debug(u"{:s}.function({!r}) : Ignoring error {:d} while trying to concretize the function type \"{:s}\".".format('.'.join([__name__, cls.__name__]), "{!s}".format(type), res, internal.utils.string.escape("{!s}".format(tinfo), '"')))
        tinfo = old if res < 0 else new

        # Now we can grab our function details and begin to process them. We
        # try to get them twice in case the layout is busted the first time.
        ftd = idaapi.func_type_data_t()
        ok = tinfo.get_func_details(ftd) or tinfo.get_func_details(ftd, idaapi.GTD_NO_ARGLOCS)
        if not ok:
            raise internal.exceptions.DisassemblerError(u"{:s}.function({!r}) : Unable to retrieve the details from the specified type information \"{:s}\".".format('.'.join([__name__, cls.__name__]), "{!s}".format(type), internal.utils.string.escape("{!s}".format(tinfo), '"')))

        # Start by gathering the result first. Since the result doesn't have a
        # name, we need to add an empty one for the purposes of consistency.
        loc, name, ti = ftd.retloc, u'', cls.copy(ftd.rettype, til)
        locinfo = cls.location_raw(loc)
        rawitems = [(name, ti, locinfo)]

        # Then we can gather the raw values from all of the parameters that exist.
        for index in builtins.range(ftd.size()):
            loc, name, ti = ftd[index].argloc, ftd[index].name, cls.copy(ftd[index].type, til)
            locinfo = cls.location_raw(loc)
            rawitems.append((internal.utils.string.of(name), ti, locinfo))

        # Now we can safely iterate through the raw items, process them
        # and then collect all of the components into a list to return.
        result = []
        for index, item in enumerate(rawitems):
            name, ti, storage = item
            ltype, linfo = storage
            location = cls.location(ti.get_size(), architecture, ltype, linfo)

            # Check to see if we got an error. We do this with a hack, by
            # doing an identity check on what was returned.
            if location is linfo:
                ltype_table = {getattr(idaapi, attribute) : attribute for attribute in dir(idaapi) if attribute.startswith('ALOC_')}
                ltype_s = ltype_table.get(ltype, '')
                logging.warning(u"{:s}.function({!r}) : Unable to handle the unsupported type {:s}({:#x}) for argument at index {:d}{:s}{:s}.".format('.'.join([__name__, cls.__name__]), "{!s}".format(type), ltype_s, ltype, index, " with the name \"{:s}\"".format(internal.utils.string.escape(name, '"')) if name else '', " of the type {!s}".format(ti) if ti.is_well_defined() else ''))

            # Now we have everything that we can pack and add to our list.
            packed = name, ti, location
            result.append(packed)
        return result

    @classmethod
    def lower_function_type(cls, type):
        '''If the given `type` has the high-level attribute (``idaapi.BFA_HIGH``), correct the types it depends on and return its lowered type.'''
        if type.is_correct() and not type.is_high_func():
            return type

        # We can only handle function pointers here.
        if not any([type.is_func(), type.is_funcptr()]):
            raise internal.exceptions.InvalidTypeOrValueError(u"{:s}.lower_function_type(\"{:s}\") : The specified type information ({!r}) is not a function and cannot be lowered.".format('.'.join([__name__, cls.__name__]), internal.utils.string.escape("{!s}".format(type), '"'), "{!s}".format(type)))

        # Create a table used to determine the string template that
        # we'll use for creating a "correct" placeholder type.
        table = [
            ('is_decl_enum', "enum {:s} {{}}".format),
            ('is_decl_struct', "struct {:s} {{}}".format),
            ('is_decl_union', "union {:s} {{}}".format),
        ]

        # Iterate through all of the "incorrect" types that belong to this
        # function, and add any partial and undefined types types to it.
        library, results = cls.library(type), []
        for _, item, _ in cls.function(type):
            if item.is_correct():
                continue

            # Make sure itś not a pointer so that we can add its contents.
            item = cls.resolve(item) if item.is_ptr() else item

            # Our type should have a name of some sort for the specific condition we're testing for.
            tname = item.get_type_name()
            if not tname:
                logging.warning(u"{:s}.lower_function_type(\"{:s}\") : The specified type information ({!r}) has no name and cannot be added to the type library.".format('.'.join([__name__, cls.__name__]), internal.utils.string.escape("{!s}".format(type), '"'), "{!s}".format(item)))
                continue

            # After snagging it, we'll re-parse it use it to create a dummy type.
            iterable = ((format, operator.methodcaller(attribute)(item)) for attribute, format in table if hasattr(item, attribute))
            available = (format(tname) for format, ok in iterable if ok)

            # Now we can use the formatspec that we extracted and render a dummy type to parse.
            definition = builtins.next(available, "{!s} {{}}".format(item))
            ti = cls.parse(library, definition, idaapi.PT_SIL)
            if not ti:
                raise internal.exceptions.InvalidTypeOrValueError(u"{:s}.lower_function_type(\"{:s}\") : The specified type information ({!r}) is an unsupported type and cannot be added to the type library as \"{:s}\".".format('.'.join([__name__, cls.__name__]), internal.utils.string.escape("{!s}".format(type), '"'), "{!s}".format(item), definition))

            # Next we'll try and add it to the type library so that the function type is well-formed.
            ordinal = cls.set_numbered_type(library, idaapi.get_type_ordinal(library, internal.utils.string.to(tname)), tname, ti)
            results.append((ordinal, item, tname, definition))

        # Finally we will make a copy of the original type, and then we can actually lower it.
        copy = cls.get(library, *type.serialize())
        lowered = type if idaapi.lower_type(library, copy) < 0 else copy

        # Now we go through our results and check if we succeeded. If we didn't, then we need to complain about it.
        if all(ordinal > 0 for ordinal, _, _, _ in results) and lowered.is_correct():
            return lowered

        errors = {getattr(idaapi, attribute) : attribute for attribute in dir(idaapi) if attribute.startswith('TERR_')}
        for code, item, tname, string in results:
            if code > 0:
                continue
            logging.warning(u"{:s}.lower_function_type(\"{:s}\") : Encountered error {:s} while trying to attach the specified type information ({!r}) to the determined name \"{:s}\".".format('.'.join([__name__, cls.__name__]), internal.utils.string.escape("{!s}".format(type), '"'), "{:s}({:d})".format(errors[code], code) if code in errors else "code ({:d})".format(code), "{!s}".format(string), internal.utils.string.escape(tname, '"')))
        return lowered

    @classmethod
    def has_ordinal(cls, ordinal, *library):
        '''Return whether the given `ordinal` is associated with a type in the specified type `library`.'''
        [library] = library if library else [None]
        til = library if library else cls.library()
        serialized = cls.get_numbered_type(til, ordinal)
        return True if serialized else False

    @classmethod
    def has_name(cls, name, *library):
        '''Return whether a type with the given `name` exists in the specified type `library`.'''
        [library] = library if library else [None]
        til = library if library else cls.library()
        ordinal = idaapi.get_type_ordinal(til, internal.utils.string.to(name))
        return True if ordinal else False

    @classmethod
    def has_struc_enum(cls, identifier, *library):
        '''Return whether the given structure, union, or enumeration `identifier` is associated with a type in the specified type `library`.'''
        identifier = identifier if isinstance(identifier, internal.types.integer) else identifier.id

        # if the identifier is not a structure/union, then check if it's an enumeration.
        sptr = idaapi.get_struc(identifier)
        if not sptr and idaapi.get_enum_idx(identifier) == idaapi.BADADDR:
            return False

        # distinguish between a structure, union, and enumeration and use it to build
        # a corresponding type_t. then, use the identifier name to get the ordinal.
        type_t = idaapi.BTMT_ENUM if not sptr else idaapi.BTMT_UNION if internal.structure.union(sptr) else idaapi.BTMT_STRUCT
        fullname = internal.netnode.name.get(idaapi.ea2node(identifier) if hasattr(idaapi, 'ea2node') else identifier)
        ordinal = idaapi.get_ordinal_from_idb_type(fullname, bytes(bytearray([idaapi.BT_COMPLEX | type_t])))

        # if we were given a type library, then verify the ordinal against its quantity.
        if library:
            return cls.has_ordinal(ordinal, *library)
        return True if ordinal else False

    @classmethod
    def anonymous_name(cls, type):
        '''Return the anonymous name for the specified `type`.'''
        serialized = type.serialize()
        defaults = [b'', b'', b'', b'', getattr(idaapi, 'sc_unk', 0), 0]
        type, fields, cmt, fields_cmt, sclass, ordinal = [item for item in itertools.chain(serialized, defaults[len(serialized) - len(defaults):])][:len(defaults)]
        return hashlib.md5(bytes().join([type, fields or b''])).hexdigest().upper()

    @classmethod
    def identifier(cls, type, *always):
        '''Return the identifier for the specified `type` from the current type library.'''
        type_description = "{:d}".format(type) if isinstance(type, internal.types.integer) else "{!r}".format("{!s}".format(type))
        tinfo = cls.for_ordinal(type) if isinstance(type, internal.types.integer) else cls.for_name(type) if isinstance(type, internal.types.string) else cls.concretize(type)

        # If we couldn't get the type using what we were given, then we abort.
        if not tinfo:
            raise internal.exceptions.ItemNotFoundError(u"{:s}.identifier({!s}{:s}) : Unable to find the specified type within the current local types library.".format('.'.join([__name__, cls.__name__]), type_description, ", {!s}".format(*always) if always else ''))

        # If we're using 8.4, then we can just process this with the new api.
        # XXX: It's worth noting that this api is not side-effect free and can
        #      result in a type being added to the library regardless of whether
        #      its "force_tid" parameter is set to true or not.
        elif idaapi.__version__ >= 8.4:
            res = idaapi.get_tinfo_tid(tinfo, *itertools.chain(always if always else [False]))
            return res

        # If it's not a type that we can return an identifier for, then raise an
        # exception since we have no way to process this on earlier than v8.4.
        elif not tinfo.is_sue():
            raise internal.exceptions.InvalidTypeOrValueError(u"{:s}.identifier({!s}{:s}) : Unable to return an identifier for the specified type due to it not being a structure, union, or enumeration.".format('.'.join([__name__, cls.__name__]), type_description, ", {!s}".format(*always) if always else ''))

        # If we got a typedef, then we need to continuously resolve it until we
        # get to a type (structure or union) that matches the type name.
        while tinfo.is_typeref():
            name = internal.utils.string.of(tinfo.get_type_name())
            candidates = (F(internal.utils.string.to(name)) for F in [idaapi.get_enum, idaapi.get_struc_id])
            if not all(candidate == idaapi.BADADDR for candidate in candidates):
                break
            ordinal = cls.ordinal(tinfo)
            tinfo = cls.at_ordinal(ordinal) if ordinal else cls.at_name(internal.utils.string.of(tinfo.get_type_name()))

        # The rest, we need to figure this out ourselves. We accomplish this by
        # concretizing the type and extracting its typename. Then we can use it
        # to look up the structure, union, or enumeration by name.
        res = cls.concretize(tinfo)
        name = internal.utils.string.of(res.get_type_name())

        tid = idaapi.get_enum(internal.utils.string.to(name)) if res.is_enum() else idaapi.get_struc_id(internal.utils.string.to(name))
        if tid == idaapi.BADADDR:
            exception_t = internal.exceptions.EnumerationNotFoundError if res.is_enum() else internal.exceptions.StructureNotFoundError
            raise exception_t(u"{:s}.identifier({!s}{:s}) : Unable to return an identifier for the specified type \"{!s}\" due to it not being a structure, union, or enumeration.".format('.'.join([__name__, cls.__name__]), type_description, ", {!s}".format(*always) if always else '', internal.utils.string.escape("{!s}".format(tinfo), '"')))
        return tid

    @classmethod
    def member_identifier(cls, type, index_or_name):
        '''Return the identifier for the specified `index_or_name` from the given `type`.'''
        type_description = "{:d}".format(type) if isinstance(type, internal.types.integer) else "{!r}".format("{!s}".format(type))
        key_description = "{:d}".format(index_or_name) if isinstance(index_or_name, internal.types.integer) else "{!r}".format(index_or_name)
        udm_t = idaapi.udt_member_t if idaapi.__version__ < 8.4 else idaapi.udm_t
        tinfo = cls.for_ordinal(type) if isinstance(type, internal.types.integer) else cls.for_name(type) if isinstance(type, internal.types.string) else cls.concretize(type)

        # If it's not a type that we can return an identifier for, then raise an
        # exception since we have no way to process this on earlier than v8.4.
        udm = udm_t()
        if not tinfo.is_sue():
            raise internal.exceptions.InvalidTypeOrValueError(u"{:s}.member_identifier({!s}, {!s}) : Unable to return an identifier for a member of the specified type due to it not being a structure, union, or enumeration.".format('.'.join([__name__, cls.__name__]), type_description, key_description))
        elif idaapi.__version__ >= 8.4 and isinstance(index_or_name, internal.types.integer):
            F, flags, udm.offset = tinfo.find_udm, idaapi.STRMEM_INDEX, index_or_name
        elif idaapi.__version__ >= 8.4 and isinstance(index_or_name, internal.types.string):
            F, flags, udm.name = tinfo.find_udm, idaapi.STRMEM_NAME, internal.utils.string.to(index_or_name)
        elif tinfo.is_enum():
            raise internal.exceptions.UnsupportedCapability(u"{:s}.member_identifier({!s}, {!s}) : Return the identifier for an enumeration is currently unimplemented.".format('.'.join([__name__, cls.__name__]), type_description, key_description))
        elif isinstance(index_or_name, internal.types.integer):
            F, flags, udm.offset = tinfo.find_udt_member, idaapi.STRMEM_INDEX, index_or_name
        elif isinstance(index_or_name, internal.types.string):
            F, flags, udm.name = tinfo.find_udt_member, idaapi.STRMEM_NAME, internal.utils.string.to(index_or_name)
        else:
            raise internal.exceptions.InvalidParameterError(u"{:s}.member_identifier({!s}, {!s}) : Unable to return an identifier for a member of the specified type using an unsupported type ({!s}).".format('.'.join([__name__, cls.__name__]), type_description, key_description, index_or_name.__class__))

        # Now we can query for the udm_t using the index or name we were given.
        res = F(udm, flags)
        if res < 0:
            raise internal.exceptions.MemberNotFoundError(u"{:s}.member_identifier({!s}, {!s}) : Unable to find a member in the given type that matches the specified {:s} ({!s}).".format('.'.join([__name__, cls.__name__]), type_description, key_description, 'index' if isinstance(index_or_name, internal.types.integer) else 'name', key_description))

        # If we're using a recent version of the disassembler, we can just use
        # the index with the `get_udm_tid` api to get the member id to return.
        if idaapi.__version__ >= 8.4:
            return tinfo.get_udm_tid(res)

        # If we're using anything else, then we need to figure the struct for
        # our type. We use the name instead of index because the disassembler
        # might include a gap that could affect the member indexing.
        sid = eid = cls.identifier(tinfo)
        if sid == idaapi.BADADDR:
            exception_t = internal.exceptions.EnumerationNotFoundError if tinfo.is_enum() else internal.exceptions.StructureNotFoundError
            raise exception_t(u"{:s}.member_identifier({!s}, {!s}) : Unable to find the identifier for the specified type ({!r}).".format('.'.join([__name__, cls.__name__]), type_description, key_description, 'index' if isinstance(index_or_name, internal.types.integer) else name, key_description, "{!s}".format(tinfo)))

        # Enumerations require us to use the enumeration api, which requires us
        # to process the `enum_type_data_t` in order to figure out the correct
        # identifier using its name or index. As such, this is unimplemented.
        if tinfo.is_enum():
            raise internal.exceptions.UnsupportedCapability(u"{:s}.member_identifier({!s}, {!s}) : Unable to find the identifier for the specified type ({!r}).".format('.'.join([__name__, cls.__name__]), type_description, key_description, 'index' if isinstance(index_or_name, internal.types.integer) else name, key_description, "{!s}".format(tinfo)))

        # Otherwise, we need to grab the structure/union using its identifier,
        # then we can use the name from `udm_t` to get the correct `member_t.`
        sptr = idaapi.get_struc(sid)
        if not sptr:
            raise internal.exceptions.StructureNotFoundError(u"{:s}.member_identifier({!s}, {!s}) : Unable to find a structure with the specified identifier ({:#x}).".format('.'.join([__name__, cls.__name__]), type_description, key_description, 'index' if isinstance(index_or_name, internal.types.integer) else name, key_description, sid))

        name = internal.utils.string.of(udm.name)
        mptr = idaapi.get_member_by_name(sptr, internal.utils.string.to(name))
        if not mptr:
            raise internal.exceptions.MemberNotFoundError(u"{:s}.member_identifier({!s}, {!s}) : Unable to find a member with the name \"{:s}\" inside the specified structure ({:#x}).".format('.'.join([__name__, cls.__name__]), type_description, key_description, 'index' if isinstance(index_or_name, internal.types.integer) else name, key_description, internal.utils.string.escape(name, '"'), sid))
        return mptr.id

    @classmethod
    def at_ordinal(cls, ordinal, *library):
        '''Return the type information for the given `ordinal` from the specified type `library`.'''
        [til] = library if library else [cls.library()]
        serialized = cls.get_numbered_type(til, ordinal)
        return cls.get(til, *serialized) if serialized else None

    @classmethod
    def at_name(cls, name, *library, **flags):
        '''Return the type information for the type with the given `name` and `flags` from a type `library`.'''
        [til] = library if library else [cls.library()]
        serialized = cls.get_named_type(til, internal.utils.string.to(name), flags.get('flags', idaapi.NTF_TYPE))
        if not serialized:
            return None

        # otherwise, we need to unpack the serialized information that was returned.
        defaults = [0, b'', b'', b'', b'', getattr(idaapi, 'sc_unk', 0), 0]
        ok, type, fields, cmt, fields_cmt, sclass, ordinal = [item for item in itertools.chain(serialized, defaults[len(serialized) - len(defaults):])][:len(defaults)]

        # we don't need the error code or the ordinal, but we'll use everything else.
        return cls.get(til, type, fields, cmt, fields_cmt, sclass) if ok else None

    @classmethod
    def by_name(cls, name, *library):
        '''Return the ordinal for the type with the given `name` from a type `library`.'''
        [til] = library if library else [cls.library()]
        ordinal = idaapi.get_type_ordinal(til, internal.utils.string.to(name))
        serialized = cls.get_numbered_type(til, ordinal)
        return ordinal if any([not library, serialized]) else 0

    @classmethod
    def by_identifier(cls, identifier, *library):
        '''Return the ordinal for the type associated with an `identifier` from the specified type `library`.'''
        identifier = identifier if isinstance(identifier, internal.types.integer) else identifier.id

        # first determine whether the identifier belongs to a structure/union/enumeration.
        sptr = idaapi.get_struc(identifier) or idaapi.get_member_by_id(identifier)
        if not sptr and idaapi.get_enum_idx(identifier) == idaapi.BADADDR:
            raise internal.exceptions.InvalidTypeOrValueError(u"{:s}.by({:#x}) : Unable to determine whether the given identifier ({:#x}) is a structure, union, or enumeration.".format('.'.join([__name__, cls.__name__]), identifier, identifier))

        # if we didn't get a struc_t, then this is a member that we need to unpack.
        # after we unpack the member and get its typeinfo, then we can get the ordinal.
        elif sptr and not isinstance(sptr, idaapi.struc_t):
            mptr, mname, mowner = sptr
            mtype = internal.structure.member.get_typeinfo(mptr)
            type_t, ordinal, fullname = mtype.get_decltype(), cls.ordinal(mtype, *library), internal.utils.string.of(mname)

        # we'll now create a type_t for whatever type it was so that we can pass
        # it to get_ordinal_from_idb_type. we will also need the full name for it.
        else:
            type_t = idaapi.BTMT_ENUM if not sptr else idaapi.BTMT_UNION if internal.structure.union(sptr) else idaapi.BTMT_STRUCT
            fullname = internal.utils.string.of(idaapi.get_struc_name(identifier) if sptr else idaapi.get_enum_name(identifier))

            # now we can call get_ordinal_from_idb_type and get the ordinal.
            ordinal = idaapi.get_ordinal_from_idb_type(internal.utils.string.to(fullname), bytes(bytearray([idaapi.BT_COMPLEX | type_t])))

        # if we got an ordinal, then we can just return it back to the caller.
        if ordinal:
            return ordinal

        # if we didn't get an ordinal, then we need to raise an exception here.
        description = {idaapi.BTMT_STRUCT: 'structure', idaapi.BTMT_UNION: 'union', idaapi.BTMT_ENUM: 'enumeration'}
        NotFoundException = internal.exceptions.StructureNotFoundError if isinstance(sptr, idaapi.struc_t) else internal.exceptions.MemberNotFoundError if sptr else internal.exceptions.EnumerationNotFoundError
        raise NotFoundException(u"{:s}.by_identifier({:#x}) : Unable to locate the type information associated with the {:s} named \"{:s}\".".format('.'.join([__name__, cls.__name__]), identifier, description.get(type_t, "identifier ({:#x})".format(identifier)), internal.utils.string.escape(fullname, '"')))

    @classmethod
    def for_ordinal(cls, ordinal, *library):
        '''Return a reference to an `ordinal` from the specified type `library`.'''
        [til] = library if library else [cls.library()]
        return cls.reference(ordinal, til)

    @classmethod
    def for_name(cls, name, *library):
        '''Return a reference to the type with the given `name` from a type `library`.'''
        [til] = library if library else [cls.library()]
        ordinal = idaapi.get_type_ordinal(til, internal.utils.string.to(name))
        return cls.reference(ordinal, *library) if ordinal else None

    @classmethod
    def for_identifier(cls, identifier, *library):
        '''Return a reference to the type associated with `identifier` from the specified type `library`.'''
        [til] = library if library else [cls.library()]
        ordinal = cls.by_identifier(identifier, til)
        return cls.reference(ordinal, *library) if ordinal else None

    @classmethod
    def bitfield(cls, type):
        '''Return the number of bits, size, and sign for the specified bitfield `type`.'''
        bf, size = idaapi.bitfield_type_data_t(), type.get_size()
        if not bf:
            sign = type.get_sign()
            return 8 * size, size, {idaapi.no_sign: 0, idaapi.type_signed: -1, idaapi.type_unsigned: +1}[sign]
        size, width = bf.nbytes, bf.width
        return width, size, +1 if bt.is_unsigned() else -1

    @classmethod
    def enumeration(cls, type):
        '''Return the base integer type of the enumeration specified by `type`.'''
        et, signedness = idaapi.enum_type_data_t(), {idaapi.no_sign: idaapi.BTMT_UNKSIGN, idaapi.type_signed: idaapi.BTMT_SIGNED, idaapi.type_unsigned: idaapi.BTMT_USIGNED}
        if not type.is_enum():
            raise internal.exceptions.InvalidTypeOrValueError(u"{:s}.enumeration({!r}) : The specified type information ({!r}) is not an enumeration.".format('.'.join([__name__, cls.__name__]), "{!s}".format(type), "{!s}".format(type)))
        elif not type.get_enum_details(et):
            raise internal.exceptions.MissingTypeOrAttribute(u"{:s}.enumeration({!r}) : Unable to get the enumeration type data from the specified type information ({!r}).".format('.'.join([__name__, cls.__name__]), "{!s}".format(type), "{!s}".format(type)))

        # Unpack the attributes from the enumeration and use it to generate an integer type.
        sz, bitmask, out = (et.bte & mask for mask in [idaapi.BTE_SIZE_MASK, idaapi.BTE_BITMASK, idaapi.BTE_OUT_MASK])
        return idaapi.tinfo_t(type.get_enum_base_type() | signedness.get(type.get_sign(), idaapi.no_sign))

    @classmethod
    def enumeration_masks(cls, type):
        '''Yield each bitmask from the enumeration bitfield specified by `type`.'''
        et, signedness = idaapi.enum_type_data_t(), {idaapi.no_sign: idaapi.BTMT_UNKSIGN, idaapi.type_signed: idaapi.BTMT_SIGNED, idaapi.type_unsigned: idaapi.BTMT_USIGNED}
        if not type.is_enum():
            raise internal.exceptions.InvalidTypeOrValueError(u"{:s}.enumeration_masks({!r}) : The specified type information ({!r}) is not an enumeration.".format('.'.join([__name__, cls.__name__]), "{!s}".format(type), "{!s}".format(type)))
        elif not type.get_enum_details(et):
            raise internal.exceptions.MissingTypeOrAttribute(u"{:s}.enumeration_masks({!r}) : Unable to get the enumeration type data from the specified type information ({!r}).".format('.'.join([__name__, cls.__name__]), "{!s}".format(type), "{!s}".format(type)))

        # First thing to do is to figure out what the base type is. We're assuming
        # that this will always be an integer so that we can add the sign to it.
        sz, bitmask, out = (et.bte & mask for mask in [idaapi.BTE_SIZE_MASK, idaapi.BTE_BITMASK, idaapi.BTE_OUT_MASK])
        bt, sign, library = type.get_enum_base_type(), type.get_sign(), cls.library(type)

        Fcast_integer = idaapi.as_signed if sign == idaapi.type_signed else lambda integer, bits: (pow(2, bits) - 1) & integer
        width, ti = et.calc_nbytes(), idaapi.tinfo_t(bt | signedness.get(sign, idaapi.no_sign))

        # Grab the indices of all of the masks that are in the bitfield, and
        # the members. Then all we need to do is yield the ones that we found.
        group_intervals = [et.group_sizes[index] for index in builtins.range(et.group_sizes.size())]
        group_indices = functools.reduce(lambda list, item: list + [list[-1] + item], group_intervals, [0])
        indices = {index : length for index, length in zip(group_indices, group_intervals)}
        iterable = (et[index] for index in builtins.range(et.size()))
        members = [tuple(itertools.chain([em.value], map(internal.utils.string.of, [em.name, em.cmt]))) for em in iterable]

        # Iterate through the list.. only yielding the enumeration members that
        # are masks. If this isn't a bitfield, then nothing should be yielded.
        for index, member in enumerate(members):
            emask, ename, ecmt = member
            if index in indices:
                yield cls.copy(ti, library), Fcast_integer(emask, 8 * width), ename, ecmt
            continue
        return

    @classmethod
    def enumeration_bitfields(cls, type):
        '''Return a dictionary of the masks and the enumeration members that use them from the bitfield specified by `type`.'''
        et, signedness = idaapi.enum_type_data_t(), {idaapi.no_sign: idaapi.BTMT_UNKSIGN, idaapi.type_signed: idaapi.BTMT_SIGNED, idaapi.type_unsigned: idaapi.BTMT_USIGNED}
        if not type.is_enum():
            raise internal.exceptions.InvalidTypeOrValueError(u"{:s}.enumeration_bitfields({!r}) : The specified type information ({!r}) is not an enumeration.".format('.'.join([__name__, cls.__name__]), "{!s}".format(type), "{!s}".format(type)))
        elif not type.get_enum_details(et):
            raise internal.exceptions.MissingTypeOrAttribute(u"{:s}.enumeration_bitfields({!r}) : Unable to get the enumeration type data from the specified type information ({!r}).".format('.'.join([__name__, cls.__name__]), "{!s}".format(type), "{!s}".format(type)))

        # If the enumeration is not a bitfield, then there's nothing to return.
        sz, bitmask, out = (et.bte & mask for mask in [idaapi.BTE_SIZE_MASK, idaapi.BTE_BITMASK, idaapi.BTE_OUT_MASK])
        if not bitmask:
            return {}

        # Now we need to figure out what the base type is. We're assuming that
        # this will always be an integer so that we can add the sign to it.
        bt, sign, library = type.get_enum_base_type(), type.get_sign(), cls.library(type)
        width, ti = et.calc_nbytes(), idaapi.tinfo_t(bt | signedness.get(sign, idaapi.no_sign))
        Fcast_integer = idaapi.as_signed if sign == idaapi.type_signed else lambda integer, bits: (pow(2, bits) - 1) & integer

        # Now we can collect the bitfield members into a list to reference.
        iterable = (et[index] for index in builtins.range(et.size()))
        members = [tuple(itertools.chain([em.value], map(internal.utils.string.of, [em.name, em.cmt]))) for em in iterable]

        # Grab the indices of all of the masks that are in the bitfield. This
        # way we can build a dictionary for looking up the bitmask for an index.
        group_intervals = [et.group_sizes[index] for index in builtins.range(et.group_sizes.size())]
        group_indices = functools.reduce(lambda list, item: list + [list[-1] + item], group_intervals, [0])
        indices = {index : length for index, length in zip(group_indices, group_intervals)}
        iterable = ((index, members[index]) for index, length in zip(group_indices, group_intervals))
        masks = {index : emask for index, (emask, ename, ecmt) in iterable}

        # Iterate through the members, using mask as a key to our results,
        # and appending each member to the list for the current bit mask.
        result, emask = {}, 0
        for index, member in enumerate(members):
            evalue, ename, ecmt = member
            emask = Fcast_integer(masks[index], 8 * width) if index in masks else emask
            if indices.get(index, 1) > 1:
                continue
            emasked_value = emask & Fcast_integer(evalue, 8 * width)
            packed = cls.copy(ti, library), emasked_value, ename, ecmt
            result.setdefault(emask, []).append(packed)
        return result

    @classmethod
    def enumeration_members(cls, type):
        '''Yield each member of the enumeration that is specified by `type`.'''
        et, signedness = idaapi.enum_type_data_t(), {idaapi.no_sign: idaapi.BTMT_UNKSIGN, idaapi.type_signed: idaapi.BTMT_SIGNED, idaapi.type_unsigned: idaapi.BTMT_USIGNED}
        if not type.is_enum():
            raise internal.exceptions.InvalidTypeOrValueError(u"{:s}.enumeration_members({!r}) : The specified type information ({!r}) is not an enumeration.".format('.'.join([__name__, cls.__name__]), "{!s}".format(type), "{!s}".format(type)))
        elif not type.get_enum_details(et):
            raise internal.exceptions.MissingTypeOrAttribute(u"{:s}.enumeration_members({!r}) : Unable to get the enumeration type data from the specified type information ({!r}).".format('.'.join([__name__, cls.__name__]), "{!s}".format(type), "{!s}".format(type)))

        # Figure out the base type for the enumeration and use it
        # to create an integer type that is fully aware of its sign.
        bt, sign, library = type.get_enum_base_type(), type.get_sign(), cls.library(type)
        width, ti = et.calc_nbytes(), idaapi.tinfo_t(bt | signedness.get(sign, idaapi.no_sign))

        Fcast_integer = idaapi.as_signed if sign == idaapi.type_signed else lambda integer, bits: (pow(2, bits) - 1) & integer
        bsz, bitmask, out = (et.bte & mask for mask in [idaapi.BTE_SIZE_MASK, idaapi.BTE_BITMASK, idaapi.BTE_OUT_MASK])

        # Grab all of the members into a list that we can check for masks.
        iterable = (et[index] for index in builtins.range(et.size()))
        members = [tuple(itertools.chain([em.value], map(internal.utils.string.of, [em.name, em.cmt]))) for em in iterable]

        # Now we just need to build a table of the indices in case this is
        # a bitfield. If so, then we'll be excluding these from our results.
        group_intervals = [et.group_sizes[index] for index in builtins.range(et.group_sizes.size())]
        group_indices = functools.reduce(lambda list, item: list + [list[-1] + item], group_intervals, [0])
        indices = {index : length for index, length in zip(group_indices, group_intervals)}
        iterable = ((index, members[index]) for index, length in zip(group_indices, group_intervals))
        masks = {index : emask for index, (emask, ename, ecmt) in iterable}

        # Yield each member from the enumeration that isn't a bitmask.
        emask = Fcast_integer(pow(2, 8 * width) - 1, 8 * width)
        for index, member in enumerate(members):
            evalue, ename, ecmt = member
            emask = Fcast_integer(masks[index], 8 * width) if index in masks else emask
            if indices.get(index, 1) > 1:
                continue
            emasked_value = emask & Fcast_integer(evalue, 8 * width)
            yield cls.copy(ti, library), emasked_value, ename, ecmt
        return

    # Table containing all of the available pointer attributes.
    _pointer_attributes = {0 : 0}
    _pointer_attributes['__ptr32'] = _pointer_attributes['ptr32'] = _pointer_attributes[idaapi.TAPTR_PTR32] = idaapi.TAPTR_PTR32
    _pointer_attributes['__ptr64'] = _pointer_attributes['ptr64'] = _pointer_attributes[idaapi.TAPTR_PTR64] = idaapi.TAPTR_PTR64
    _pointer_attributes['__restrict'] = _pointer_attributes['restrict'] = _pointer_attributes[idaapi.TAPTR_RESTRICT] = idaapi.TAPTR_RESTRICT

    # If shifted pointers are available, then include support for those too.
    if hasattr(idaapi, 'TAPTR_SHIFTED'):
        _pointer_attributes['__shifted'] = _pointer_attributes['shifted'] = _pointer_attributes[idaapi.TAPTR_SHIFTED] = idaapi.TAPTR_SHIFTED
        _pointer_attributes['__shift'] = _pointer_attributes['shift'] = _pointer_attributes[idaapi.TAPTR_SHIFTED]

    # FIXME: It'd be nice if we verified the attributes we are being given
    #        against the ptr_type_data_t fields that need to be populated.

    @classmethod
    def pointer_attributes(cls, attributes):
        '''Converts the given `attributes` that can be specified as an integer, string, or iterable into its matching ``idaapi.TAPTR_`` attributes.'''
        if isinstance(attributes, (internal.types.string, internal.types.integer)):
            attribute = attributes if isinstance(attributes, internal.types.integer) else attributes.lower()
            if attribute in cls._pointer_attributes:
                return idaapi.TAH_HASATTRS | cls._pointer_attributes[attribute] if cls._pointer_attributes[attribute] else 0
            format_parameter, format_description = ("{:#x}".format, "{:d}".format) if isinstance(attributes, internal.types.integer) else ("{!r}".format, lambda attribute: "\"{:s}\"".format(internal.utils.string.escape(attributes, '"')))
            raise internal.exceptions.InvalidParameterError(u"{:s}.pointer_attributes({:s}) : Unable to determine the correct pointer attribute for the given value ({:s}).".format('.'.join([__name__, cls.__name__]), format_parameter(attributes), format_description(attributes)))

        # Otherwise we were given an iterable and we need to convert and reduce each item.
        normalized = [(item.lower() if isinstance(item, internal.types.string) else item) for item in attributes]
        unique = {cls._pointer_attributes.get(attribute, attribute) for attribute in normalized}
        if any(integer not in cls._pointer_attributes for integer in unique):
            iterable = (item for item in res if item not in cls._pointer_attributes)
            invalid = [("{:#x}".format(item) if isinstance(item, internal.types.integer) else "{!r}".format(item)) for item in iterable]
            raise internal.exceptions.InvalidParameterError(u"{:s}.pointer_attributes({!r}) : Unable to determine the pointer attributes for {:d} of the {:d} suggested values ({!r}).".format('.'.join([__name__, cls.__name__]), attributes, len(invalid), len(unique), invalid))

        # Reduce all of the items we were given into something for ptr_type_data_t.taptr_bits.
        return functools.reduce(operator.or_, unique, idaapi.TAH_HASATTRS if any(unique) else 0)

    @classmethod
    def reduce(cls, type, *size):
        '''Reduce the `type` with the given `size` down to a type composed of integer types.'''
        ti = tinfo.parse(None, type) if isinstance(type, internal.types.string) else type

        # create some tables that we'll use to reduce types with.
        masks = [idaapi.TYPE_BASE_MASK, idaapi.TYPE_FLAGS_MASK, idaapi.TYPE_MODIF_MASK]
        integer_sizes = {
            1: idaapi.BTMT_SIZE12 | idaapi.BT_VOID,
            2: idaapi.BTMT_SIZE12 | idaapi.BT_UNK,
            4: idaapi.BTMT_SIZE48 | idaapi.BT_VOID,
            8: idaapi.BTMT_SIZE48 | idaapi.BT_UNK,
            16: idaapi.BTMT_SIZE128 | idaapi.BT_VOID,
        }
        brute_factor = sorted(integer_sizes)[::-1]
        word_size, _ = divmod(database.bits(), 8)

        # define a closure for recursively reducing the types composing a type.
        def reduce_individual_type(ti, *parameter):
            '''Reduce the type specified in `ti` down to its base integer type.'''
            decl, [size] = ti.get_decltype(), parameter if parameter else [ti.get_size()]

            # unpack the type's declaration into its individual components.
            base, flags, modifiers = (decl & mask for mask in masks)

            # if it's a complex type that's a typedef, then we only need to
            # extract what it targets and then recurse to find the base type.
            if (base, flags) in {(idaapi.BT_COMPLEX, idaapi.BTMT_TYPEDEF)}:
                til = ti.get_til()

                # figure out whether we received the type by ordinal or name. if
                # it was name, then query the type library for it and recurse.
                ordinal = ti.get_ordinal()
                if ordinal > 0:
                    nexttype = tinfo.at_ordinal(ordinal, til)
                elif ti.get_type_name():
                    name = internal.utils.string.of(ti.get_type_name())
                    nexttype = tinfo.at_name(name, til)
                else:
                    raise internal.exceptions.MissingTypeOrAttribute(u"{:s}.reduce_individual_type({!r}{:s}) : Unable to determine whether the specified type information ({!r}) is a numbered or named type.".format('.'.join([__name__, cls.__name__]), "{!s}".format(ti), ", {:d}".format(size) if parameter else '', "{!s}".format(ti)))
                return reduce_individual_type(nexttype)

            # if it's any other complex type, then we simply return an array
            # based on the largest integer factor of the udt alignment.
            elif (base, flags) in {(idaapi.BT_COMPLEX, idaapi.BTMT_STRUCT), (idaapi.BT_COMPLEX, idaapi.BTMT_UNION)}:
                utd = idaapi.udt_type_data_t()
                if not ti.has_details():
                    raise internal.exceptions.MissingTypeOrAttribute(u"{:s}.reduce_individual_type({!r}{:s}) : The specified type information ({!r}) does not contain any details.".format('.'.join([__name__, cls.__name__]), "{!s}".format(ti), ", {:d}".format(size) if parameter else '', "{!s}".format(ti)))
                elif not ti.is_udt():
                    raise internal.exceptions.InvalidTypeOrValueError(u"{:s}.reduce_individual_type({!r}{:s}) : The specified type information ({!r}) is not a structure or union.".format('.'.join([__name__, cls.__name__]), "{!s}".format(ti), ", {:d}".format(size) if parameter else '', "{!s}".format(ti)))
                elif not ti.get_udt_details(utd):
                    raise internal.exceptions.DisassemblerError(u"{:s}.reduce_individual_type({!r}{:s}) : Unable to get the member data from the specified type information ({!r}).".format('.'.join([__name__, cls.__name__]), "{!s}".format(ti), ", {:d}".format(size) if parameter else '', "{!s}".format(ti)))

                # grab the alignment and use it to figure out the largest factor.
                alignment = max(1, utd.effalign)
                iterable = ((item, divmod(size, item)) for item in brute_factor)
                filtered = (item for item, (quotient, remainder) in iterable if not remainder)

                # we need to choose a factor, but we instead use the word size
                # as the maximum factor instead of the available integer sizes.
                available = (item for item in filtered if item <= word_size)
                factor = next(available, integer_sizes[1])

                # now we can figure out the array element type.
                length, remainder = divmod(size, factor)
                element = idaapi.tinfo_t(integer_sizes[factor])

                # and then create our array with it.
                atd, newtype = idaapi.array_type_data_t(), idaapi.tinfo_t()
                atd.base, atd.nelems, atd.elem_type = 0, length, element

                if not newtype.create_array(atd):
                    raise internal.exceptions.DisassemblerError(u"{:s}.reduce_individual_type({!r}{:s}) : Unable to create an array of type \"{:s}\" with {:d} element{:s} from the specified type information ({!r}).".format('.'.join([__name__, cls.__name__]), "{!s}".format(ti), ", {:d}".format(size) if parameter else '', internal.utils.string.escape("{!s}".format(element), '"'), length, "{!s}".format(ti)))
                return newtype

            # if it's an enumeration, then we use its width to figure the type.
            elif (base, flags) in {(idaapi.BT_COMPLEX, idaapi.BTMT_ENUM)}:
                etd = idaapi.enum_type_data_t()
                if not ti.has_details():
                    raise internal.exceptions.MissingTypeOrAttribute(u"{:s}.reduce_individual_type({!r}{:s}) : The specified type information ({!r}) does not contain any details.".format('.'.join([__name__, cls.__name__]), "{!s}".format(ti), ", {:d}".format(size) if parameter else '', "{!s}".format(ti)))
                elif not ti.is_enum():
                    raise internal.exceptions.InvalidTypeOrValueError(u"{:s}.reduce_individual_type({!r}{:s}) : The specified type information ({!r}) is not an enumeration.".format('.'.join([__name__, cls.__name__]), "{!s}".format(ti), ", {:d}".format(size) if parameter else '', "{!s}".format(ti)))
                elif not ti.get_enum_details(etd):
                    raise internal.exceptions.DisassemblerError(u"{:s}.reduce_individual_type({!r}{:s}) : Unable to get the enumeration type data from the specified type information ({!r}).".format('.'.join([__name__, cls.__name__]), "{!s}".format(ti), ", {:d}".format(size) if parameter else '', "{!s}".format(ti)))

                # get the size of the enumeration and find the integer that fits it.
                nbytes = etd.calc_nbytes()
                iterable = ((item, divmod(size, item)) for item in brute_factor)
                filtered = (item for item, (quotient, remainder) in iterable if not remainder)

                # get the factor and use it to create the integer type to return.
                factor = next(filtered, integer_sizes[1])
                newtype = idaapi.tinfo_t(integer_sizes[factor])
                return newtype

            # if it's an array, then we reduce its element and re-create it.
            elif base in {idaapi.BT_ARRAY}:
                atd = idaapi.array_type_data_t()
                if not ti.has_details():
                    raise internal.exceptions.MissingTypeOrAttribute(u"{:s}.reduce_individual_type({!r}{:s}) : The specified type information ({!r}) does not contain any details.".format('.'.join([__name__, cls.__name__]), "{!s}".format(ti), ", {:d}".format(size) if parameter else '', "{!s}".format(ti)))
                elif not ti.is_array():
                    raise internal.exceptions.InvalidTypeOrValueError(u"{:s}.reduce_individual_type({!r}{:s}) : The specified type information ({!r}) is not an array.".format('.'.join([__name__, cls.__name__]), "{!s}".format(ti), ", {:d}".format(size) if parameter else '', "{!s}".format(ti)))
                elif not ti.get_array_details(atd):
                    raise internal.exceptions.DisassemblerError(u"{:s}.reduce_individual_type({!r}{:s}) : Unable to get the array type data from the specified type information ({!r}).".format('.'.join([__name__, cls.__name__]), "{!s}".format(ti), ", {:d}".format(size) if parameter else '', "{!s}".format(ti)))

                # unpack all the fields that compose the array to extract the
                # element and count, and then reduce the array element.
                index, length, element = atd.base, atd.nelems, tinfo.copy(atd.elem_type)
                newelement = reduce_individual_type(element, element.get_size())

                # create a new array_type_data_t using the fields we unpacked.
                atd, newtype = idaapi.array_type_data_t(), idaapi.tinfo_t()
                atd.base, atd.nelems, atd.elem_type = index, length, newelement

                # now we can create an array and return it.
                if not newtype.create_array(atd):
                    raise internal.exceptions.DisassemblerError(u"{:s}.reduce_individual_type({!r}{:s}) : Unable to create an array of type \"{:s}\" with the extracted base ({:d}) and length ({:d}).".format('.'.join([__name__, cls.__name__]), "{!s}".format(ti), ", {:d}".format(size) if parameter else '', internal.utils.string.escape("{!s}".format(ti), '"'), index, length))
                return newtype

            # if it's a function, then we reduce all of its members but preserve
            # the calling convention.
            elif base in {idaapi.BT_FUNC}:
                info, ftd = tinfo.prototype_details(ti)

                # grab all the types that are used for the result and parameters
                # of the function. we then reduce each of them to their base type.
                count = ftd.size()
                iterable = itertools.chain([ftd.rettype], (ftd[index].type for index in builtins.range(ftd.size())))
                newtypes = [reduce_individual_type(item) for item in map(tinfo.copy, iterable)]

                # now can repopulate our func_type_data_t with the reduced types.
                iterable = iter(newtypes)
                ftd.rettype = next(iterable)
                for index, newtype in enumerate(iterable):
                    ftd[index].type = newtype

                # after doing everything, we can then create the function and return it.
                if not info.create_func(ftd):
                    raise internal.exceptions.DisassemblerError(u"{:s}.reduce_individual_type({!r}{:s}) : Unable to create a function with the extracted types from \"{:s}\".".format('.'.join([__name__, cls.__name__]), "{!s}".format(ti), ", {:d}".format(size) if parameter else '', internal.utils.string.escape("{!s}".format(ti), '"')))
                return info

            # bitfields are easy since they're packed into an integer of some size.
            elif base in {idaapi.BT_BITFIELD}:
                btd = idaapi.bitfield_type_data_t()
                if not ti.has_details():
                    raise internal.exceptions.MissingTypeOrAttribute(u"{:s}.reduce_individual_type({!r}{:s}) : The specified type information ({!r}) does not contain any details.".format('.'.join([__name__, cls.__name__]), "{!s}".format(ti), ", {:d}".format(size) if parameter else '', "{!s}".format(ti)))
                elif not ti.is_bitfield():
                    raise internal.exceptions.InvalidTypeOrValueError(u"{:s}.reduce_individual_type({!r}{:s}) : The specified type information ({!r}) is not a bitfield.".format('.'.join([__name__, cls.__name__]), "{!s}".format(ti), ", {:d}".format(size) if parameter else '', "{!s}".format(ti)))
                elif not ti.get_bitfield_details(btd):
                    raise internal.exceptions.DisassemblerError(u"{:s}.reduce_individual_type({!r}{:s}) : Unable to get the bitfield type data from the specified type information ({!r}).".format('.'.join([__name__, cls.__name__]), "{!s}".format(ti), ", {:d}".format(size) if parameter else '', "{!s}".format(ti)))

                # we can simply use the number of bytes and bits inside the
                # bitfield_type_data_t to figure out which integer to use.
                nbytes = btd.nbytes
                return idaapi.tinfo_t(integer_sizes[nbytes])

            # any other type should be integer-like which means we can just use
            # its size to find a base integer type that can fit it.
            iterable = ((item, divmod(size, item)) for item in brute_factor)
            filtered = (item for item, (quotient, remainder) in iterable if not remainder)
            factor = next(filtered, integer_sizes[1])
            newtype = idaapi.tinfo_t(integer_sizes[factor])
            return newtype

        return reduce_individual_type(ti, *size)

    @classmethod
    def basic(cls, type, *integer_flags):
        '''Return whether the given `type` is a default data type (without modifiers) chosen by the disassembler with the selected compiler.'''
        decl = type.get_decltype()

        # assign some types that we'll use for our checks. in order to allow
        # using this same function with signed and unsigned compiler integers,
        # we take any flags we were given and create mask to test them with.
        masks = [idaapi.TYPE_BASE_MASK, idaapi.TYPE_FLAGS_MASK, idaapi.TYPE_MODIF_MASK]
        integer_flags_mask = operator.invert(*integer_flags) if integer_flags else idaapi.TYPE_FLAGS_MASK

        # XXX: it's worth noting that our referral to these being "basic" types
        #      is different from the documentation. we classify a "basic" type
        #      as a type that is made using the data types rather than a type
        #      applied using type information.

        compiler_integer_types = {
            idaapi.BT_INT8,
            idaapi.BT_INT16,
            idaapi.BT_INT32,
            idaapi.BT_INT64,
            idaapi.BT_INT128,
            idaapi.BT_INT,
        }

        # We also treat the primitive types that have practically no information
        # associated with them as a basic type.
        void_types = {
            idaapi.BTMT_SIZE0,
            idaapi.BTMT_SIZE12,
            idaapi.BTMT_SIZE48,
            idaapi.BTMT_SIZE128,
        }

        # unpack the type declaration into its components so that we can test.
        base, flags, modifiers = (decl & mask for mask in masks)

        # if there are any modifiers, then its definitely not a basic type.
        if modifiers:
            return False

        # start out by checking if it's a user-specified basic type. these
        # include things like _BYTE, _WORD, _DWORD, _QWORD, and _OWORD.
        if base in {idaapi.BT_VOID, idaapi.BT_UNK} and flags in void_types:
            return True

        # now we can check if it's one of the basic integer types used by the
        # compiler.
        elif not (flags & integer_flags_mask) and base in compiler_integer_types:
            return True

        # we need to specially handle single-byte types, because they have a
        # special flag set for them to make them into a "char".
        elif (base, flags) == (idaapi.BT_INT8, idaapi.BTMT_CHAR):
            return True

        # floating-point numbers require us to test the flags for the type.
        elif base == idaapi.BT_FLOAT and flags in {idaapi.BTMT_FLOAT, idaapi.BTMT_DOUBLE, idaapi.BTMT_SPECFLT}:
            return True

        # anything else was explicitly specified by the user or decompiler.
        return False

    @classmethod
    def compiler(cls, type):
        '''Return whether the given `type` is used by the selected compiler (without modifiers) including signed or unsigned attributes.'''
        flags = idaapi.BTMT_SIGNED | idaapi.BTMT_UNSIGNED
        return cls.basic(type, flags)

    @classmethod
    def boolean(cls, type, *sizes):
        '''Return whether the given `type` is a boolean type per the selected compiler.'''
        masks = [idaapi.TYPE_BASE_MASK, idaapi.TYPE_FLAGS_MASK, idaapi.TYPE_MODIF_MASK]

        # This table is used to map sizes to the flags for a boolean type. If we
        # were given any sizes, then we use the table to build a set that we can
        # use to check if one of the sizes were selected. It's worth noting that
        # the existence of a 2-byte or 8-byte boolean depends on the database.
        boolean_sizes = {
            1 : idaapi.BTMT_BOOL1,
            2 : idaapi.BTMT_BOOL2,
            8 : idaapi.BTMT_BOOL8,
            4 : idaapi.BTMT_BOOL4,
        }

        remove = {8} if database.bits() != 64 else {2}
        filtered = {size for size in sizes} - removed if sizes else boolean_sizes.keys()
        requested = {boolean_sizes[size] for size in filtered} | {0}

        # Grab the declaration type and unpack all of its components so that we
        # can test them. Booleans are easy since there's only one type to check.
        decl = type.get_decltype()
        base, flags, modifiers = (decl & mask for mask in masks)
        return base == idaapi.BT_BOOL and not modifiers and flags in requested

    @classmethod
    def quoted(cls, type):
        '''Format the specified `type` as a double-quoted and escaped string.'''
        masks = [idaapi.TYPE_BASE_MASK, idaapi.TYPE_FLAGS_MASK, idaapi.TYPE_MODIF_MASK]

        # XXX: so, as i complained about to support...it turns out that the type
        #      is racy as shit and can give us a busted type that raises an
        #      internal error when trying to access any of its type attributes.
        #      this means things like `tinfo_t.is_correct`, `tinfo.is_present`,
        #      and most importantly rendering it as a string is fucking busted.

        # To work around the above issue, we search for malformed types using
        # apis that don't try to access the type's attributes. This limits us to
        # explicitly checking the `tinfo_t.typid` directly for an unknown type.
        tinfo, decl = type, type.get_decltype()
        base, flags, modifiers = (decl & mask for mask in masks)

        # If we got an unknown type, then don't even attempt to render it.
        if base == idaapi.BT_UNK and flags == idaapi.BTMT_SIZE128:
            return '<UNKNOWN>'

        # Hopefully we can just try to render it as a string without any issues.
        string = "{!s}".format(tinfo)
        escaped = internal.utils.string.escape(string, '"')
        return "\"{:s}\"".format(escaped)

def tuplename(*names):
    '''Given a tuple as a name, return a single name joined by "_" characters.'''
    iterable = (("{:x}".format(abs(int(item))) if isinstance(item, internal.types.integer) or hasattr(item, '__int__') else item) for item in names)
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

    def __equality__(self, operation, other):
        cls = self.__class__
        if isinstance(other, internal.types.integer):
            return operation(*map(int, [self, other]))
        elif isinstance(other, self.__class__) and self.__same__(other):
            return operation(*map(tuple, [self, other]))
        return operation(True, False)

    def __comparison__(self, operation, other):
        cls = self.__class__
        if not isinstance(other, internal.types.integer) and isinstance(other, self.__class__) and self.__same__(other):
            return operation(*map(tuple, [self, other]))
        elif not isinstance(other, (internal.types.integer, integerish)):
            raise TypeError(u"{:s}.__comparison__({!s}, {!r}) : Unable to perform {:s} operation with type `{:s}` due to a dissimilarity with type `{:s}`.".format('.'.join([__name__, cls.__name__]), operation, other, operation.__name__, other.__class__.__name__, cls.__name__))
        return operation(*map(int, [self, other]))

    # equality
    def __eq__(self, other):
        return self.__equality__(operator.eq, other)
    def __hash__(self):
        items = internal.types.tuple(self)
        return hash(items)

    # comparisons
    def __lt__(self, other):
        return self.__comparison__(operator.lt, other)
    def __le__(self, other):
        return self.__comparison__(operator.le, other)
    def __gt__(self, other):
        return self.__comparison__(operator.gt, other)
    def __ge__(self, other):
        return self.__comparison__(operator.ge, other)

    # ...because py2 does not understand reflexivity
    if sys.version_info.major < 3:
        def __ne__(self, other):
            return self.__equality__(operator.ne, other)
        def __cmp__(self, other):
            return -1 if self.__operator__(operator.lt, other) else +1 if self.__operator__(operator.gt, other) else 0

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
        bytes, bits = divmod(self.__size__, 8)
        return 1 + bytes if bits else bytes
    @property
    def position(self):
        '''Return the binary offset of the current register into its full register that contains it.'''
        return self.__position__
    @property
    def type(self):
        '''Return the pythonic type of the register.'''
        bytes, bits = divmod(self.__size__, 8)
        return self.__ptype__, 1 + bytes if bits else bytes

    def __description__(self):
        '''Return a short description of the current register using its class and name.'''
        cls = register_t
        return "{:s}<{:s}>".format(cls.__name__, self.name)

    def __format__(self, spec):
        '''Format the register as either an object or a string using its name.'''
        prefix = getattr(self.architecture, 'prefix', '') if hasattr(self, 'architecture') else ''

        # If no formatspec was given, then we include the architecture prefix and
        # treat it as a register that needs to be distinguished from other symbols.
        if not spec:
            return prefix + self.name

        # If the register is being formatted as a string, then we exclude the
        # architecture prefix because the name is being used explicitly.
        elif spec == 's':
            return self.name

        # Otherwise we bitch and complain about what the caller attempted to do.
        cls = self.__class__
        raise internal.exceptions.InvalidParameterError(u"{:s}.format({!r}) : Unable to format the specified register using an unsupported format code ({!s}).".format(self.__description__(), spec, spec))

    # When the register is implicitly converted to a string (like when it
    # is directly passed to `print`), we include the architecture prefix.
    def __str__(self):
        '''Return the architecture's register prefix concatenated to the register's name.'''
        prefix = getattr(self.architecture, 'prefix', '') if hasattr(self, 'architecture') else ''
        return prefix + self.name

    # If the caller wants the representation of the register, then we try
    # to make it look like a python type but including additional attributes.
    def __repr__(self):
        '''Return the register formatted as an instance of an object with additional attributes.'''
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
            raise internal.exceptions.DisassemblerError(u"{:s}.int() : Unable to fetch the integer for the value of the associated register ({}) using its name ({!r}).".format(self.__description__(), self, rname))
        mask = pow(2, self.bits) - 1
        if rv.rvtype == idaapi.RVT_INT:
            return rv.ival & mask
        elif rv.rvtype == idaapi.RVT_FLOAT:
            logging.warning(u"{:s}.int() : Converting a non-integer register type ({:d}) to an integer using {:d} bytes.".format(self.__description__(), rv.rvtype, self.size))
            bytes = rv.fval.bytes
        else:
            logging.warning(u"{:s}.int() : Converting a non-integer register type ({:d}) to an integer using {:d} bytes.".format(self.__description__(), rv.rvtype, self.size))
            bytes = rv.bytes()
        return functools.reduce(lambda agg, item: agg * 0x100 + item, bytearray(bytes), 0)

    def __float__(self):
        '''Return the floating-point value of the current register.'''
        rv, rname = idaapi.regval_t(), self.name
        if not idaapi.get_reg_val(rname, rv):
            raise internal.exceptions.DisassemblerError(u"{:s}.float() : Unable to fetch the floating-point number for the value of the associated register ({}) using its name ({!r}).".format(self.__description__(), self, rname))
        if rv.rvtype == idaapi.RVT_FLOAT:
            return rv.fval._get_float()
        raise internal.exceptions.InvalidTypeOrValueError(u"{:s}.float() : Unable to concretize an unknown register value type ({:d}) to a floating-point number.".format(self.__description__(), rv.rvtype))

    @property
    def bytes(self):
        '''Return the bytes that make up the value of the current register.'''
        rv, rname = idaapi.regval_t(), self.name
        if not idaapi.get_reg_val(rname, rv):
            raise internal.exceptions.DisassemblerError(u"{:s}.bytes : Unable to fetch the bytes for the value of the associated register ({}) using its name ({!r}).".format(self.__description__(), self, rname))
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
    def opinfo(cls, ea, opnum):
        '''Return the ``idaapi.opinfo_t`` for the operand `opnum` belonging to the instruction at address `ea`.'''
        info, flags = idaapi.opinfo_t(), address.flags(ea)
        ok = idaapi.get_opinfo(ea, opnum, flags, info) if idaapi.__version__ < 7.0 else idaapi.get_opinfo(info, ea, opnum, flags)
        return info if ok else None

    @classmethod
    def access_75(cls, ea):
        '''Yield the ``opref_t`` for each operand belonging to the instruction at address `ea`.'''
        READ, WRITE, MODIFY = getattr(idaapi, 'READ_ACCESS', 2), getattr(idaapi, 'WRITE_ACCESS', 1), getattr(idaapi, 'RW_ACCESS', 3)
        get_operand_size = internal.utils.fcompose(*[operator.attrgetter('dtyp'), idaapi.get_dtyp_size] if idaapi.__version__ < 7.0 else [operator.attrgetter('dtype'), idaapi.get_dtype_size])
        ea, architecture_word_size = int(ea), database.bits() // 8

        # Get the register accesses for the instruction.
        ra, insn, flags = idaapi.reg_accesses_t(), instruction.at(ea), address.flags(ea)
        sflags = idaapi.sval_pointer(); sflags.assign(idaapi.extend_sign(flags, 4, True))
        iflags = idaapi.int_pointer(); iflags.assign(sflags.value())
        if not idaapi.ph_get_reg_accesses(ra, insn, iflags.value()):
            return

        # Grab the features and create some tools for accesing them.
        features = cls.feature(ea)
        Ffeature, Fflag = map(functools.partial(functools.partial, operator.and_), [features, flags])

        # Get all the instruction-specific attributes that are relevant to the access_t of each operand.
        is_call, is_jump, is_shift = cls.is_call(ea), cls.is_branch(ea), cls.is_shift(ea)
        operands, MS_XTYPE = cls.operands(ea), Fflag(idaapi.MS_0TYPE | idaapi.MS_1TYPE)

        # Grab all of the register accesses for the instruction grouped by opnum.
        accesses, iterable = {}, (ra[index] for index in builtins.range(ra.size()))
        [accesses.setdefault(item.opnum, []).append((item.access_type, item.regnum, item.range.bitoff(), item.range.bitsize())) for item in iterable]

        # First we create tables that map the operand type to an xref flag. These contain
        # the base flag to use when constructing an access_t prior to it being modified.
        xref_call_table, xref_jump_table = {
            idaapi.o_near: idaapi.fl_CN,
            idaapi.o_far: idaapi.fl_CF,
            idaapi.o_mem: idaapi.fl_CF,
            idaapi.o_displ: idaapi.fl_CF,
        }, {
            idaapi.o_near: idaapi.fl_JN,
            idaapi.o_far: idaapi.fl_JF,
            idaapi.o_mem: idaapi.fl_JF,
            idaapi.o_displ: idaapi.fl_JF,
        }

        # Now we can grab the operands and use them to yield each access. Branches and
        # instructions get different semantics in that branches will always execute ('x')
        # an address. The only difference is whether they load ('r') it or not. Regular
        # instructions will read ('r') or write ('w') to their operand. However, if it's
        # loading or storing to an address, then '&' will be used to signify that.
        for opnum, op in enumerate(cls.operands(ea)):
            word_sized, access = get_operand_size(op) == architecture_word_size, accesses.get(opnum, ())
            used, modified = Ffeature(cls.uses_bits[opnum]), Ffeature(cls.changes_bits[opnum])
            adds_xrefs = idaapi.op_adds_xrefs(flags, opnum) and op.type != idaapi.o_reg and not idaapi.is_enum(flags, opnum)

            # If this is a call, then we only need to distinguish whether it loads from
            # some address. So the only two states, are loading from an address or not.
            if Ffeature(idaapi.CF_CALL):
                reftype = xref_call_table.get(op.type, idaapi.fl_CF if word_sized else idaapi.fl_CN)
                check = op.type in {idaapi.o_displ, idaapi.o_phrase} if access else op.type in {idaapi.o_mem}
                loading = True if Ffeature(idaapi.CF_JUMP) and op.type in {idaapi.o_displ, idaapi.o_phrase, idaapi.o_mem} else False
                assert(check == loading), "{:s}.access_75({:#x}) : Operand {:d} of {:s} instruction with access ({!s}) is not an expected operand type ({:d}).".format('.'.join([__name__, cls.__name__]), ea, opnum, ' and '.join(feature for feature in ['CF_CALL', 'CF_JUMP'] if Ffeature(getattr(idaapi, feature))) or 'unknown', access, op.type)
                realaccess = access_t(reftype, True) | 'r' if loading else access_t(reftype, True)

            # If it's a jump, then we essentially do the same thing as a call. The
            # only thing that's different is the base reftype used for the access_t.
            elif is_jump:
                reftype = xref_jump_table.get(op.type, idaapi.fl_JF if word_sized else idaapi.fl_JN)
                check = op.type in {idaapi.o_displ} if not access else op.type in {idaapi.o_mem}
                loading = True if Ffeature(idaapi.CF_JUMP) and op.type not in {idaapi.o_reg} else False
                mod = 'w' if modified else 'r'
                realaccess = access_t(reftype, True) | mod if loading else access_t(reftype, True)

            # If the operand is both used and modified, then we check everything.
            # If any are being modified (WRITE), then this is being updated. If
            # none of the registers are modified then it's used for storing.
            elif modified and used:
                storing = all(item[0] & MODIFY != WRITE for item in access)
                modifying = any(item[0] & MODIFY == WRITE for item in access)
                referencing = adds_xrefs or op.type in {idaapi.o_mem, idaapi.o_displ, idaapi.o_phrase}
                res = access_t(idaapi.dr_W, False) | 'r' if storing or modifying else access_t(idaapi.dr_R, False)
                realaccess = res | '&' if referencing else res

            # If the operand is just being used, then we only need to check if it's
            # an immediate and/or it's referencing a memory address type.
            elif used and not modified:
                referencing = adds_xrefs if op.type in {idaapi.o_imm} else op.type in {idaapi.o_mem, idaapi.o_displ, idaapi.o_phrase}
                reftype = idaapi.fl_USobsolete if op.type in {idaapi.o_imm} else idaapi.dr_R
                realaccess = access_t(reftype, False) | '&' if referencing else access_t(reftype, False)

            # If the operand is being modified, then it's only storing if all the
            # registers are being read from. Then if the operand is an address type
            # that could have references we add the '&' for it.
            elif modified and not used:
                storing = all(item[0] & MODIFY == READ for item in access)
                referencing = adds_xrefs or op.type in {idaapi.o_mem, idaapi.o_displ, idaapi.o_phrase}
                realaccess = access_t(idaapi.dr_W, False) | '&' if referencing or storing else access_t(idaapi.dr_W, False)

            # If there's no registers accesses, then we only need to specially handle
            # immediates and operands that will add xrefs.
            else:
                reftype = idaapi.fl_USobsolete if op.type in {idaapi.o_imm} else idaapi.dr_W if modified else idaapi.dr_R
                referencing = adds_xrefs
                realaccess = access_t(reftype, False) | '&' if referencing else access_t(reftype, False)

            # Now we can just yield the correct access inside an opref_t for the caller.
            yield opref_t(ea, opnum, realaccess)
        return

    @classmethod
    def access_74(cls, ea):
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
                idaapi.o_imm: [idaapi.fl_USobsolete, getattr(idaapi, 'dr_U', 0)],
            }, [idaapi.dr_R, idaapi.dr_W]

        # Iterate through all of the operands and yield their access_t.
        for opnum, op in enumerate(operands):
            used, modified = Ffeature(cls.uses_bits[opnum]), Ffeature(cls.changes_bits[opnum])
            ri, has_xrefs = address.refinfo(ea, opnum), idaapi.op_adds_xrefs(flags, opnum) and not idaapi.is_enum(flags, opnum)

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
            elif op.type in {idaapi.o_mem, idaapi.o_phrase, idaapi.o_displ}:
                access = access | '&'
            yield opref_t(ea, opnum, access)
        return
    access = access_74 if idaapi.__version__ < 7.5 else access_75

    @classmethod
    def reference(cls, ea, opnum, refinfo=None):
        '''Return the address being referenced for operand `opnum` at instruction address `ea` using the specified `refinfo` if it is available.'''
        get_dtype_attribute = operator.attrgetter('dtyp' if idaapi.__version__ < 7.0 else 'dtype')
        get_dtype_size = idaapi.get_dtyp_size if idaapi.__version__ < 7.0 else idaapi.get_dtype_size

        # Grab the instruction, its operand, and then its value. We also grab its dtype in case
        # we can't treat it as a reference meaning we have to fall back to it as an immediate.
        ea, insn, operand = int(ea), instruction.at(ea), instruction.operand(ea, opnum)
        dtype, value = get_dtype_attribute(operand), operand.value if operand.type in {idaapi.o_imm} else operand.addr

        # If we weren't given a refinfo_t, then we figure it out from the default. So, unless
        # the user changed it, the default should always result in returning the immediate.
        if not refinfo:
            default = idaapi.refinfo_t()
            default.set_type(idaapi.get_default_reftype(insn.ea))
            default.base, default.target = 0, idaapi.BADADDR

            # Although there's other operand types we can support, we don't take a chance and only handle
            # immediates. If the user really wants it, they can grab the refinfo_t themselves and do it.
            if operand.type not in {idaapi.o_mem, idaapi.o_near, idaapi.o_far, idaapi.o_imm}:
                raise internal.exceptions.InvalidTypeOrValueError(u"{:s}.reference({:#x}, {:d}, {!s}) : Unable to determine the reference type for the instruction at address {:#x} due to its operand ({:d}) being an unsupported type ({:d}).".format('.'.join([__name__, cls.__name__]), ea, opnum, refinfo, insn.ea, operand.n, operand.type))
            refinfo = default

        # Now we need to calculate the reference target which requires the operand value to be
        # an adiff_t. This type is really the same as an sval_t, so we use an sval_pointer for it.
        ea, sval, target = idaapi.ea_pointer(), idaapi.sval_pointer(), idaapi.ea_pointer()
        ea.assign(insn.ea), sval.assign(value)
        if hasattr(idaapi, 'calc_reference_data'):
            ok = idaapi.calc_reference_data(target.cast(), ea.cast(), insn.ea, refinfo, sval.value())

        # And because I'm an idiot that supports versions of the disassembler that are mad old...
        else:
            res = idaapi.calc_reference_target(ea.value(), refinfo, sval.value())
            ok, _ = res != idaapi.BADADDR, target.assign(res)

        # If the target can't be calculated and the operand is an immediate, then we need to treat it
        # as a regular operand honoring negation or signedness and returning the correct value.
        if not ok and operand.type in {idaapi.o_imm}:
            bits = 8 * get_dtype_size(dtype)
            avalue, maximum = idaapi.as_signed(value, bits), pow(2, bits)
            signed, unsigned = (value - maximum, value) if avalue > 0 else (avalue, value & (maximum - 1))
            return signed if node.alt_opinverted(insn.ea, operand.n) else unsigned
        return target.value() if ok else value

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
        target = ea if idaapi.__version__ < 7.0 else cls.at(ea if isinstance(ea, internal.types.integer) else ea.ea)

        # XXX: turns out that `is_ret_insn` doesn't work for every return
        #      instruction on the Intel processor. from digging, it seems
        #      that it's based on testing a supval in "$ vmm functions".
        #      so, as a work around we clear the supval before using it.
        #      i'm not sure what other processor modules are affected.

        # FIXME: this netnode is only used for the pc and pc64 processor
        #        modules. we really should be using whatever netnode name is
        #        being used by the currently selected processor, just in case
        #        this issue exists in any of the other processor modules.
        node, tag = '$ vmm functions', 'r'

        # if there's no supval for this address, then we can trust it.
        ea = ea if isinstance(target, internal.types.integer) else target.ea
        if not internal.netnode.sup.has(node, idaapi.ea2node(ea), tag=tag):
            return True if idaapi.is_ret_insn(target) else False

        # first we preserve the original supval and remove it for the address.
        preserved = internal.netnode.sup.get(node, idaapi.ea2node(ea), tag=tag)
        removed = internal.netnode.sup.remove(node, idaapi.ea2node(ea), tag=tag)

        # now we can use the `is_ret_insn` api in its working form and then
        # we'll need to restore the value that was just preserved.
        try:
            ok = idaapi.is_ret_insn(target)
        finally:
            restored = internal.netnode.sup.set(node, idaapi.ea2node(ea), preserved, tag=tag)
        return True if ok else False

    @classmethod
    def is_indirect(cls, ea):
        '''Return whether the instruction at the address `ea` is an unconditional (indirect) branch instruction.'''
        target, bbargs = (ea, []) if idaapi.__version__ < 7.0 else (cls.at(ea), [False])
        if hasattr(idaapi, 'is_indirect_jump_insn'):
            return True if idaapi.is_indirect_jump_insn(target) else False
        features, invalid, expected = cls.feature(ea), any([idaapi.is_call_insn(target), cls.is_return(target)]), idaapi.CF_STOP | idaapi.CF_JUMP
        ok = idaapi.is_basic_block_end(target, *bbargs) and not invalid and features & expected == expected
        return True if ok else False

    @classmethod
    def is_unconditional(cls, ea):
        '''Return whether the instruction at the address `ea` is an unconditional (direct and indirect) branch instruction.'''
        features, expected = cls.feature(ea), idaapi.CF_STOP | idaapi.CF_HLL
        target, bbargs = (ea, []) if idaapi.__version__ < 7.0 else (cls.at(ea), [False])
        ok = idaapi.is_basic_block_end(target, *bbargs) and not cls.is_return(target) and features & expected == expected
        return True if ok else False

    @classmethod
    def is_conditional(cls, ea):
        '''Return whether the instruction at the address `ea` is an conditional branch instruction.'''
        target, bbargs = (ea, []) if idaapi.__version__ < 7.0 else (cls.at(ea), [False])
        feature, invalid = cls.feature(ea), any([idaapi.is_call_insn(target), cls.is_return(target)])
        xiterable = (True for _, xiscode, xrtype in xref.of(ea) if xiscode and xrtype != idaapi.fl_F)
        ok = idaapi.is_basic_block_end(target, *bbargs) and not invalid and not feature & idaapi.CF_STOP and next(xiterable, False)
        return True if ok else False

    @classmethod
    def boundaries(cls, ea):
        '''Return a list of boundaries for the operands belonging to the instruction at address `ea`.'''
        heap, ops, operands, insn = [], {}, cls.operands(ea), cls.at(ea)
        [(heapq.heappush(heap, operand.offb), ops.setdefault(operand.offb, []).append(index)) for index, operand in enumerate(operands)]

        # it would be neat if we could identify modrm/sib and adjust our list
        # of points to reference them without being architecture-specific.
        points = [heapq.heappop(heap) for heap in len(heap) * [heap]] + [insn.size]
        bounds = {ops[point].pop(0) : (points[index], points[index + 1]) for index, point in enumerate(points[:-1])}
        iterable = (map(functools.partial(operator.add, insn.ea), bounds[index]) for index, _ in enumerate(operands))
        return [bounds_t(*bounds) for bounds in iterable]

    @classmethod
    def arguments(cls, ea):
        '''Return the initialization address for each of the parameters being passed to the function reference at `ea`.'''
        [is_call, is_branch] = (F(ea) for F in [cls.is_call, cls.is_branch])
        if not (is_call or is_branch):
            raise internal.exceptions.InvalidTypeOrValueError(u"{:s}.arguments({:#x}) : The instruction at the specified address ({:#x}) is not a call or branch instruction.".format('.'.join([__name__, cls.__name__]), ea, ea))
        elif is_branch and not xref.has_code(ea, descend=True):
            raise internal.exceptions.MissingTypeOrAttribute(u"{:s}.arguments({:#x}) : Unable to return parameters for the branch at the provided address ({:#x}) due to it not having any code references.".format('.'.join([__name__, cls.__name__]), ea, ea))

        # Grab the argument addresses from the PIT and verify that we got them
        # if the instruction is a branch instruction. If the instruction is a
        # call instruction, then we always return some number of parameters.
        items = idaapi.get_arg_addrs(ea)
        if items is None and not is_call:
            raise internal.exceptions.DisassemblerError(u"{:s}.arguments({:#x}) : Unable to retrieve the initialization addresses for the parameters passed to the instruction at {:#x}.".format('.'.join([__name__, cls.__name__]), ea, ea))

        # If we received a BADADDR for any of the addresses, then replace it.
        mapped = map(lambda ea: None if ea == idaapi.BADADDR else ea, items or [])
        return [ea for ea in mapped]

class regmatch(object):
    """
    This namespace is used to assist with doing register matching
    against instructions. This allows one to request the operand
    references for an address and only return the ones that match
    any number of registers that are written to or read from. By
    taking the difference of the result, you can also return
    the operands that do not use any registers.
    """

    def __new__(cls, *registers, **modifiers):
        '''Return a closure that filters the operand references for an instruction using the specified `registers` and `modifiers`.'''
        use, select = cls.use(*registers), cls.modifier(**modifiers)
        def match_access(ea):
            iterable = filter(use, select(ea)) if registers else select(ea)
            return tuple(ref for ref in iterable)
        return match_access

    @classmethod
    def use(cls, *registers):
        '''Return a closure that checks if an operand reference uses any of the specified `registers`.'''
        import __catalog__ as catalog

        # convert any registers that are strings into a register_t object.
        choices = { architecture.by_name(reg) if isinstance(reg, internal.types.string) else reg for reg in registers }

        # returns whether the register in operand is a subset of any of the given registers.
        match = (lambda registers: lambda operand: any(map(operand.related, registers)))(choices)

        # returns true if the operand at the specified address is composed of one of the specified `registers`.
        def operand_uses_register(ea, opnum, *access):
            insn, operand = instruction.at(ea), instruction.operand(ea, opnum)
            op = catalog.operand.decode(insn, operand)
            if isinstance(op, symbol_t):
                return any(map(match, op.symbols))
            return False

        # return a wrapper that can take an address and opnum or an opref_t.
        def uses_register(ref, *args):
            return operand_uses_register(ref, *args) if args else operand_uses_register(*ref)
        return uses_register

    # Operand groups for the different modifiers that may be specified.
    # FIXME: These are processor-specific and belong in the architecture module.
    __operands_all__ = {op for op in builtins.range(idaapi.o_void + 1, 0x20)}
    __operands_register__ = {
        idaapi.o_reg, idaapi.o_phrase, idaapi.o_displ, idaapi.o_mem} | {
        idaapi.o_idpspec0, idaapi.o_idpspec1, idaapi.o_idpspec2,
        idaapi.o_idpspec3, idaapi.o_idpspec4, idaapi.o_idpspec5,
        idaapi.o_idpspec5 + 1, idaapi.o_idpspec5 + 2
    }
    __operands_memory__ = {idaapi.o_mem, idaapi.o_displ, idaapi.o_phrase}
    __operands_branch__ = {idaapi.o_near, idaapi.o_far, idaapi.o_mem}

    @classmethod
    def modifier(cls, **modifiers):
        '''Return a closure that filters the operands references for an address using any of the specified `modifiers`.'''
        utils = internal.utils

        # define a few closures that we can use for filtering access and operand groups
        Fneeds_access = lambda mask, flags: utils.fcompose(operator.itemgetter(-1), internal.types.set, functools.partial(operator.and_, {flag for flag in mask}), lambda available: [flag in available for flag in mask], all)
        Fuses_group = lambda group: utils.fcompose(operator.itemgetter(slice(None, -1)), utils.funpack(instruction.operand), operator.attrgetter('type'), functools.partial(operator.contains, group))

        # define all of the available modifier parameters
        load_args, store_args = {'load', 'loaded'}, {'store', 'stored'}

        read_args = {'read', 'r'}
        write_args = {'written', 'write', 'w'}
        modify_args = {'modify', 'modified', 'changed', 'readwrite', 'rw'}
        execute_args = {'executed', 'execute', 'exec', 'x'}

        # start by reading all of the modifiers from the parameters.
        modifiers_used = {modifier for modifier in modifiers}

        has_load = modifiers_used & load_args
        load = next((modifiers[item] for item in load_args if item in modifiers), None) if modifiers_used & load_args else None
        has_store = modifiers_used & store_args
        store = next((modifiers[item] for item in store_args if item in modifiers), None) if modifiers_used & store_args else None
        has_memory = modifiers_used & (load_args | store_args)

        has_read, has_write, has_modify, has_execute = (modifiers_used & args for args in [read_args, write_args, modify_args, execute_args])
        read, write, modify, execute = (next((modifiers[item] for item in args if item in modifiers), None) for args in [read_args, write_args, modify_args, execute_args])

        # if we're being asked to filter for a memory operand, then we need
        # to always test the memory operands and ensure there is at least one
        # condition. this also affects the operand group that read/write/modify
        # uses. so, for them to work, we make sure to update that at the end.
        F, conditions = None, []
        if has_memory:
            Fload = utils.fcompose(utils.fthrough(Fuses_group(cls.__operands_memory__), Fneeds_access('r', 'r')), all)
            F = Fload if load else utils.fnot(Fload)
            conditions.append(F) if has_load else conditions

            Fstore = utils.fcompose(utils.fthrough(Fuses_group(cls.__operands_memory__), Fneeds_access('w', 'w')), all)
            F = Fstore if store else utils.fnot(Fstore)
            conditions.append(F) if has_store else conditions

            # we need to ensure that memory operands are explicitly tested for.
            default_operand_group = cls.__operands_register__ | cls.__operands_memory__

        # if no loads/stores were specified, then we can use the "registers" operand
        # group for everything except for the executable modifier which uses branches.
        else:
            default_operand_group = cls.__operands_register__

        # now we can do the regular bits using the determined operand group.
        # FIXME: we should probably pull out the operand group conditon, since it
        #        only needs to happen once if any of the "has_*" variables are set.
        for has, needs, bits in zip([has_read, has_write, has_modify], [read, write, modify], ['r', 'w', 'rw']):
            if has and needs:
                F = utils.fcompose(utils.fthrough(Fuses_group(default_operand_group), Fneeds_access(bits, bits)), all)
            elif has:
                F = utils.fnot(Fneeds_access(bits, bits))
            conditions.append(F) if has else conditions

        # the execute bit only matters for branch operands.
        if has_execute and execute:
            F = utils.fcompose(utils.fthrough(Fuses_group(cls.__operands_branch__), Fneeds_access('x', 'x')), all)
        elif has_execute:
            F = utils.fnot(Fneeds_access('x', ''))
        conditions.append(F) if has_execute else conditions

        # if we couldn't determine any conditions, then we constrain to the register group.
        Fconditions = utils.fcompose(utils.fthrough(*conditions), all) if conditions else Fuses_group(cls.__operands_register__)
        return internal.utils.fcompose(instruction.access, functools.partial(internal.utils.ifilter, Fconditions), functools.partial(sorted, key=operator.attrgetter('opnum')))

class typematch(object):
    """
    This namespace is intended to enable one to match or filter
    a list of types and its subtypes. This is done by creating a
    dictionary from each selected type that is composed of their
    base declaration type, flags, and their modifiers.

    These three type declaration attributes are used in combination
    to produce three levels of keys that are queried in order of
    decreasing levels of detail. The first key type includes any
    modifiers, along with the standard base declaration type and
    flags to allow explicitly specifying a modifier to search for.
    The other two key types include the base type and its flags,
    or if nothing was found, the general base declaration type.

    The function for this namespace is responsible for taking
    a list of desired types and converting it into a collection
    that can then be used for matching. Once the collection has
    been created, it is then usable with other functions from
    the namespace to match and filter an arbitrary list of types.

    There are other tools in this namespace that recursively
    yield all of the subtypes that may compose a specific
    type. These are intended to be used to generate a stream
    of subtypes that can be used when matching a collection
    in order to allow selecting matching members of a structure,
    parameters and result from a prototype, or scalars that
    are of the same base type despite any attribute modifiers
    that they may have.

    Some ways to utilize this namespace are::

        > collection = typematch(['signed long', 'char[]', 'struct mystruc**'])
        > print( typematch.use(collection, type_or_prototype) )
        > print( typematch.like(collection, type_or_prototype) )
        > for subtype, matches in typematch.select(collection, type_or_prototype): ...
        > for candidate in typematch.candidates(collection, sometype): ...

    """

    masks = [idaapi.TYPE_BASE_MASK, idaapi.TYPE_FLAGS_MASK, idaapi.TYPE_MODIF_MASK]
    full_type = {idaapi.BT_VOID, idaapi.BT_BOOL, idaapi.BT_FLOAT, idaapi.BT_COMPLEX}
    integer_types = {idaapi.BT_INT8, idaapi.BT_INT16, idaapi.BT_INT32, idaapi.BT_INT64, idaapi.BT_INT128, idaapi.BT_INT}
    integer_sizes = {1: idaapi.BT_INT8, 2: idaapi.BT_INT16, 4: idaapi.BT_INT32, 8: idaapi.BT_INT64, 16: idaapi.BT_INT128}
    flags_optional = {idaapi.BT_FUNC, idaapi.BT_BITFIELD}
    flags_none = {idaapi.BT_PTR, idaapi.BT_ARRAY, idaapi.BT_UNK}

    def __new__(cls, types, *library):
        '''Reduce the list of `types` into a dictionary that can be used with other functions in this namespace.'''
        [til] = library if library else [tinfo.library()]
        iterable = ((tinfo.parse(til, item) if isinstance(item, internal.types.string) else item) for item in types)
        res, errors, candidates = {}, [], [type for type in iterable if type]
        for ti in candidates:
            decl, size = ti.get_decltype(), ti.get_size()
            base, flags, modifiers = (decl & mask for mask in cls.masks)

            # if it's a typeref, then we figure out whether it has an ordinal,
            # a name, or both so that we can use it as a key for an exact match.
            if (base, flags) == (idaapi.BT_COMPLEX, idaapi.BTMT_TYPEDEF):
                keys = [ti.get_ordinal(), ti.get_type_name()]
                [res.setdefault(key, [ti]) for key in keys if key]

            # if we need the full type to check this, then use all masks as the key.
            if base in cls.full_type:
                key = (base, flags, modifiers) if modifiers else (base, flags)
                res.setdefault(key, []).append(ti)

            # if the flags are optional, then add the full type and the fallback.
            elif base in cls.flags_optional:
                key = (base, flags, modifiers) if modifiers else (base, flags)
                res.setdefault(key, []).append(ti)
                res.setdefault((base,), []).append(ti)

            # if it's a processor integer type, then we treat it as an regular
            # int, but with the additional matching depending on its size.
            elif base == idaapi.BT_INT and size in cls.integer_sizes and flags:
                newbase = cls.integer_sizes[size]
                keypart = (flags, modifiers) if modifiers else (flags,)

                key = (base,) + keypart
                res.setdefault(key, []).append(ti)
                res.setdefault((base,), []).append(ti)

                key = (newbase,) + keypart
                res.setdefault(key, []).append(ti)
                res.setdefault((newbase,), []).append(ti)

            # if there aren't any flags, then we use -1 as the key so that
            # we can check the modifiers of the type's declaration.
            elif base == idaapi.BT_INT and size in cls.integer_sizes and not flags:
                newbase = cls.integer_sizes[size]
                res.setdefault((base, -1, modifiers), []).append(ti) if modifiers else res.setdefault((base,), []).append(ti)
                res.setdefault((newbase, -1, modifiers), []).append(ti) if modifiers else res.setdefault((newbase,), []).append(ti)

            # if it's an integer type, then we need to check if the sign was
            # given. we also need to know its size if it's a processor int.
            elif base in cls.integer_types and modifiers:
                keypart = (flags, modifiers) if flags else (-1, modifiers)
                res.setdefault((base,) + keypart, []).append(ti)
                res.setdefault((base,), []).append(ti)

            elif base in cls.integer_types:
                res.setdefault((base, flags), []).append(ti) if flags else ()
                res.setdefault((base,), []).append(ti)

            # if we don't need the flags, then just include the base.
            elif base in cls.flags_none:
                res.setdefault((base, -1, modifiers), []).append(ti) if modifiers else res.setdefault((base,), []).append(ti)

            # we have no idea what this is.. capture it so we can log a warning.
            else:
                errors.append((base, flags, modifiers, ti))
            continue

        # if we didn't encounter any errors, then we're done here.
        if not errors:
            return res

        description = ', '.join("{!r}".format("{!s}".format(ti)) for ti in candidates)
        for base, flags, modifiers, ti in errors:
            logging.warning(u"{:s}.typematch({:s}) : Unable to index the unsupported \"{:s}\" type due to its base declaration ({:#x}), flags ({:#x}), or modifiers ({:#x}).".format('.'.join([__name__, cls.__name__]), '[' + description + ']', internal.utils.string.escape("{!s}".format(ti), '"'), base, flags, modifiers))
        return res

    @classmethod
    def unpack(cls, type):
        '''Unpack the unique attributes from the specified `type` as its identity.'''
        decl, size, name = type.get_decltype(), type.get_size(), type.get_type_name() or ''

        # We only need the fields if it's a base type. We also assume
        # that the type that we get is _always_ going to be a named type.
        if decl < idaapi.BT_PTR:
            base, flags, modifiers = (decl & mask for mask in cls.masks)
            return base, flags, modifiers, -1 if size == idaapi.BADSIZE else size, name

        # If the type nests others, then take a performance hit and hash
        # the serialized data with names and everything. This is because
        # I couldn't find another way to generate a unique key for them.
        serialized = type.serialize()
        return hash(serialized[0]), len(serialized[0]), name

    @classmethod
    def collect_types_from_library(cls, library, types):
        '''Yield each type composing all of the specified `types` from a type `library`.'''
        Fnamed_type = functools.partial(idaapi.replace_ordinal_typerefs, library) if hasattr(idaapi, 'replace_ordinal_typerefs') else None

        # Shove the type into our queue, and begin processing its components.
        queue, refs = [type for type in types], {ref for ref in []}
        while queue:
            ti = queue.pop(0)

            # We attempt to force every type into a named type so that we
            # can use the serialized data as the key when it's complex.
            Fnamed_type and idaapi.replace_ordinal_typerefs(library, ti)
            key, decl = cls.unpack(ti), ti.get_decltype()
            base, flags, modifiers = (decl & mask for mask in cls.masks)

            # If the key used to represent our type has
            # already been queued, then we can skip it.
            if key in refs:
                continue
            refs.add(key)

            # Type references allow for recursion, so we need to check these.
            if ti.is_typeref():
                name, ordinal = ti.get_type_name(), tinfo.ordinal(ti, library)
                keys = [ordinal, name] if ordinal else [name]
                if any(key in refs for key in keys):
                    [ refs.setdefault(key, ti) for key in keys ]
                    continue
                subtype = tinfo.at_ordinal(ordinal, library) if ordinal else tinfo.at_name(name, library)
                queue.append(subtype) if subtype else queue

            # If it's a pointer, then we dereference until we get to a concrete type.
            elif ti.is_ptr():
                subtype, components = ti, []
                while subtype.is_ptr():
                    subtype = idaapi.remove_pointer(subtype)
                    components.append(subtype)
                queue.extend(components)

            # An array only requires us to know its element type.
            elif ti.is_array():
                subtype, count = tinfo.array(ti)
                queue.append(subtype)

            # If we're processing a function, we need its result and parameters.
            elif ti.is_func():
                iterable = (subtype for _, subtype, _ in tinfo.function(ti))
                queue.extend(iterable)

            # If it's a struct/union, then we need all of its members.
            elif ti.is_udt():
                iterable = (mtype for mname, moffset, msize, mtype, malign in tinfo.members(ti))
                queue.extend(iterable)

            # If it's an enumeration, then we only need to queue up its base type.
            elif ti.is_enum():
                subtype = tinfo.enumeration(ti)
                queue.append(subtype)

            # If it's an integer, boolean, or floating-point type, then queue
            # variations of the type without its flags or individual modifiers.
            elif ti.is_bool() or ti.is_int() or ti.is_float():
                if modifiers == idaapi.BTM_CONST | idaapi.BTM_VOLATILE:
                    queue.append(idaapi.tinfo_t(base | flags | idaapi.BTM_CONST))
                    queue.append(idaapi.tinfo_t(base | flags | idaapi.BTM_VOLATILE))

                elif modifiers:
                    queue.append(idaapi.tinfo_t(base | flags))

                flags and queue.append(idaapi.tinfo_t(base))

            # All of the type's components have been processed, so
            # we only need to yield a copy of it back to the caller.
            yield tinfo.copy(ti, library)
        return

    @classmethod
    def collect_scalars_from_types(cls, library, types):
        '''Yield each scalar type composing the specified `types` from a type `library`.'''
        Fnamed_type = functools.partial(idaapi.replace_ordinal_typerefs, library) if hasattr(idaapi, 'replace_ordinal_typerefs') else None

        # Shove the type into our queue, and begin processing its components.
        queue, refs = [type for type in types], {ref for ref in []}
        while queue:
            ti = queue.pop(0)

            # We attempt to force every type into a named type so that we
            # can use the serialized data as the key when it's complex.
            Fnamed_type and Fnamed_type(ti)
            key = cls.unpack(ti)

            # If the key used to represent our type has
            # already been queued, then we can skip it.
            if key in refs:
                continue
            refs.add(key)

            # Type references allow for recursion, so we need to check these.
            if ti.is_typeref():
                name, ordinal = ti.get_type_name(), tinfo.ordinal(ti, library)
                keys = [ordinal, name] if ordinal else [name]
                if any(key in refs for key in keys):
                    [ refs.setdefault(key, ti) for key in keys ]
                    continue
                subtype = tinfo.at_ordinal(ordinal, library) if ordinal else tinfo.at_name(name, library)
                queue.append(subtype) if subtype else queue

            # If it's a pointer, then we dereference until we get to a concrete type.
            elif ti.is_ptr():
                subtype, components = ti, []
                while subtype.is_ptr():
                    subtype = idaapi.remove_pointer(subtype)
                    components.append(subtype)
                queue.extend(components)

            # If it's an enumeration, then we only need to queue up its base type.
            elif ti.is_enum():
                subtype = tinfo.enumeration(ti)
                queue.append(subtype)

            # All of the type's components have been processed, so
            # we only need to yield a copy of it back to the caller.
            yield tinfo.copy(ti, library)
        return

    @classmethod
    def collect_scalars_from_type(cls, type):
        '''Yield each scalar type that the specified `type` is composed of.'''
        library = tinfo.library(type)
        return cls.collect_scalars_from_types(library, [type])

    @classmethod
    def collect_types_from_type(cls, type):
        '''Recursively yield each individual type that composes the specified `type`.'''
        library = tinfo.library(type)
        return cls.collect_types_from_library(library, [type])

    @classmethod
    def collect_types_from_prototype(cls, prototype):
        '''Recursively yield each individual type that composes the specified function `prototype`.'''
        library, iterable = tinfo.library(type), itertools.chain((subtype for _, subtype, _ in tinfo.function(prototype)), [prototype])
        return cls.collect_scalars_from_types(library, [type for type in iterable])

    @classmethod
    def collect_scalars_from_pointer(cls, library, type):
        '''Yield each scalar type for the specified pointer `type` from a type `library`.'''
        bytes, fields, comments = type.serialize()
        data = bytearray(bytes)

        # If it's not a pointer, then there's nothing for us to yield.
        if not type.is_ptr():
            return

        # Figure out the index to use for slicing the base type of the pointer.
        iterable = (index for index, byte in enumerate(data) if byte & idaapi.TYPE_BASE_MASK != idaapi.BT_PTR)
        index = next(iterable)

        # Slice up the serialized data to extract the declaration. This way we
        # can yield the pointer type without its modifiers and its flags.
        slice, [decl], remaining = data[:index], data[index : index + 1], data[index + 1:]
        base, flags, modifiers = (decl & mask for mask in cls.masks)

        if modifiers == idaapi.BTM_CONST | idaapi.BTM_VOLATILE:
            yield tinfo.get(library, slice + bytearray([base | flags | idaapi.BTM_CONST]) + remaining, fields, comments)
            yield tinfo.get(library, slice + bytearray([base | flags | idaapi.BTM_VOLATILE]) + remaining, fields, comments)

        elif modifiers:
            yield tinfo.get(library, slice + bytearray([base | flags]) + remaining, fields, comments)

        if flags and base != idaapi.BT_COMPLEX:
            yield tinfo.get(library, slice + bytearray([base]) + remaining, fields, comments)

        # Go through and remove a dereference from the pointer type so that we
        # can serialize the pointer type and slice up its declaration type.
        subtype = type
        while subtype.is_ptr():
            subtype = idaapi.remove_pointer(subtype)
            yield tinfo.copy(subtype, library)

            bytes, fields, comments = subtype.serialize()
            data = bytearray(bytes)

            # Determine the index that we'll need to use to extract the base
            # type for the pointer by skipping over all the BT_PTR bytes.
            iterable = (index for index, byte in enumerate(data) if byte & idaapi.TYPE_BASE_MASK != idaapi.BT_PTR)
            index = next(iterable)

            # Slice up the serialized data so that we can extract its
            # declaration type. Then we can yield a variation of the current
            # pointer type without its modifiers and without its flags.
            slice, [decl], remaining = data[:index], data[index : index + 1], data[index + 1:]
            base, flags, modifiers = (decl & mask for mask in cls.masks)

            if modifiers == idaapi.BTM_CONST | idaapi.BTM_VOLATILE:
                yield tinfo.get(library, slice + bytearray([base | flags | idaapi.BTM_CONST]) + remaining, fields, comments)
                yield tinfo.get(library, slice + bytearray([base | flags | idaapi.BTM_VOLATILE]) + remaining, fields, comments)

            elif modifiers:
                yield tinfo.get(library, slice + bytearray([base | flags]) + remaining, fields, comments)

            if flags and base != idaapi.BT_COMPLEX:
                yield tinfo.get(library, slice + bytearray([base]) + remaining, fields, comments)
            continue
        return

    @classmethod
    def candidates(cls, collection, type):
        '''Return all candidates from the specified `collection` that may match the given `type`.'''
        decl = type.get_decltype()

        # Unpack the base type, flags, and any modifiers
        # from the declaration of the type we were given.
        base, flags, modifiers = (decl & mask for mask in cls.masks)

        # If there are modifiers in the type declaration, then we first attempt to use them to
        # find any candidates from the collection that explicitly contain the same modifiers.
        if modifiers:
            key_full = (base, flags, modifiers)
            key_noflags = (base, -1, modifiers)
            return collection.get(key_full, collection.get(key_noflags, collection.get((base,), [])))

        # Otherwise we try to find candidates from the collection that match the base declaration
        # type along with its flags. If that didn't work, then we fall back to just the base type.
        key_flags = (base, flags)
        return collection.get(key_flags, collection.get((base,), []))

    @classmethod
    def __select_subtypes__(cls, collection, subtypes):
        '''Yield each subtype from the specified `subtypes` that match a type from the given `collection`.'''
        for subtype in subtypes:
            key = subtype.get_ordinal() or subtype.get_type_name()
            candidates = collection[key] if key in collection else cls.candidates(collection, subtype)
            if any(tinfo.equals(ti, subtype) for ti in candidates):
                yield subtype, candidates
            continue
        return

    @classmethod
    def use(cls, collection, type):
        '''Return whether the specified `type` is composed of any of the types from the given `collection`.'''
        subtypes = cls.collect_types_from_prototype(type) if type.is_func() or type.is_funcptr() else cls.collect_types_from_type(type)
        iterable = cls.__select_subtypes__(collection, subtypes)
        return True if next(iterable, False) else False

    @classmethod
    def select(cls, collection, type):
        '''Yield each subtype from the specified `type` that match a type from the given `collection`.'''
        subtypes = cls.collect_types_from_prototype(type) if type.is_func() or type.is_funcptr() else cls.collect_types_from_type(type)
        for subtype, candidates in cls.__select_subtypes__(collection, subtypes):
            yield subtype, candidates
        return

    @classmethod
    def like(cls, collection, type):
        '''Return whether the specified `type` is related to any of the types from the given `collection`.'''
        subtypes = cls.collect_scalars_from_type(type)
        iterable = cls.__select_subtypes__(collection, subtypes)
        return True if next(iterable, False) else False

## figure out the boundaries of sval_t
if idaapi.BADADDR == 0xffffffff:
    sval_t = ctypes.c_long
elif idaapi.BADADDR == 0xffffffffffffffff:
    sval_t = ctypes.c_longlong
else:
    sval_t = ctypes.c_int
    logging.fatal(u"{:s} : Unable to determine size of idaapi.BADADDR in order to determine boundaries of sval_t. Setting default size to {:d}-bits. The value of idaapi.BADADDR is {!r}.".format(__name__, ctypes.sizeof(sval_t), idaapi.BADADDR))

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

        # symbolic constant (enum)
        getattr(idaapi, 'dr_S', 6): 0,

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

    # If we're code, then 'x' (1) should pretty much always be set.
    # If we're not code and neither '&' (8), 'r' (4), or 'w' (2) is set, it's actually '&' (8) unless a symbolic constant (dr_S).
    # If the reftype is the fl_USobsolete backdoor, then we ignore all enforcement.
    @classmethod
    def __adjust_flags__(cls, xrtype, iscode, flag):
        ignore_mask, required_set = (14, 0 if xrtype == idaapi.dr_S else 8) if not iscode else (0, 1) if xrtype in cls.__xftypes__ else (0, 0)
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

    def __contains__(self, other):
        operation = operator.contains
        if not isinstance(other, internal.types.string):
            cls = self.__class__
            raise TypeError(u"{:s}.__contains__({!s}, {!r}) : Unable to perform {:s} operation with a type ({:s}) that is not a string.".format('.'.join([__name__, cls.__name__]), self, other, 'membership', other.__class__.__name__))
        return any(operation(item, other) for item in tuple(self) if isinstance(item, (reftype_t, access_t)))

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

    # These are just wrappers that were (mostly) moved from the database.xref namespace.
    @classmethod
    def any(cls, ea, descend):
        '''Return a ``ref_t`` for each location that references the address `ea` (if `descend` is false), or that is referenced by the address `ea`.'''
        grouped, order, xiterate = {}, [], cls.of if descend else cls.to
        for xr, iscode, xrtype in xiterate(ea):
            if any([iscode and xrtype != idaapi.fl_F, not iscode]):
                _, items = (None, grouped[xr]) if xr in grouped else (order.append(xr), grouped.setdefault(xr, []))
                items.append(ref_t(xr, access_t(xrtype, iscode)))
            continue

        # Now we just need to merge them and yield them in the same order that we collected them.
        for ea, items in zip(order, map(functools.partial(operator.getitem, grouped), order)):
            yield functools.reduce(operator.or_, items)
        return

    @classmethod
    def code(cls, ea, descend):
        '''Return a ``ref_t`` for each location that references the address `ea` as code (if `descend` is false), or that is referenced by the address `ea`.'''
        xiterate = cls.of if descend else cls.to
        for xr, iscode, xrtype in xiterate(ea):
            if iscode and xrtype != idaapi.fl_F:
                yield ref_t(xr, access_t(xrtype, iscode))
            continue
        return

    @classmethod
    def data(cls, ea, descend):
        '''Return a ``ref_t`` for each location that references the address `ea` as data (if `descend` is false), or that is referenced by the address `ea`.'''
        xiterate = cls.of if descend else cls.to
        for xr, iscode, xrtype in xiterate(ea):
            if not iscode:
                yield ref_t(xr, access_t(xrtype, iscode))
            continue
        return

    @classmethod
    def any_address(cls, ea, descend):
        '''Return each address that references the address `ea` (if `descend` is false), or that is referenced by the address `ea`.'''
        xiterate = cls.of if descend else cls.to
        for xr, iscode, xrtype in xiterate(ea):
            if any([iscode and xrtype != idaapi.fl_F, not iscode]):
                yield xr
            continue
        return

    @classmethod
    def code_address(cls, ea, descend):
        '''Return each address that references the address `ea` as code (if `descend` is false), or that is referenced by the address `ea`.'''
        xiterate = cls.of if descend else cls.to
        for xr, iscode, xrtype in xiterate(ea):
            if iscode and xrtype != idaapi.fl_F:
                yield xr
            continue
        return

    @classmethod
    def data_address(cls, ea, descend):
        '''Return each address that references the address `ea` as data (if `descend` is false), or that is referenced by the address `ea`.'''
        xiterate = cls.of if descend else cls.to
        for xr, iscode, _ in xiterate(ea):
            if not iscode:
                yield xr
            continue
        return

    @classmethod
    def has(cls, ea, descend):
        '''Return if there is a reference to the address `ea` (if `descend` is false), or from the address if otherwise.'''
        if descend:
            return next(cls.any_address(ea, True), None) is not None
        return True if address.flags(ea) & idaapi.FF_REF else False

    @classmethod
    def has_code(cls, ea, descend):
        '''Return if there is a code reference to the address `ea` (if `descend` is false), or from the address if otherwise.'''
        return next(cls.code_address(ea, descend), None) is not None

    @classmethod
    def has_data(cls, ea, descend):
        '''Return if there is a data reference to the address `ea` (if `descend` is false), or from the address if otherwise.'''
        return next(cls.data_address(ea, descend), None) is not None

    @classmethod
    def structure(cls, sptr):
        '''Yield each structure or frame member referencing the structure identified by `sptr` as a tuple composed of the offset and reference type or member.'''
        results, this = [], idaapi.get_struc(sptr if isinstance(sptr, internal.types.integer) else sptr.id)

        # Iterate through each reference for the structure to determine what it was
        # actually applied to. If the reference is an identifier, then we need to know
        # the mptr, full name, and sptr to identify what is actually being referenced.
        for xrfrom, xriscode, xrtype in cls.to(this.id, idaapi.XREF_ALL):
            if node.identifier(xrfrom):
                mpack = idaapi.get_member_by_id(xrfrom)
                if mpack is None:
                    raise internal.exceptions.MemberNotFoundError(u"{:s}.structure({:#x}) : Unable to locate the member identified by {:#x}.".format('.'.join([__name__, cls.__name__]), this.id, xrfrom))

                mptr, name, sptr = mpack
                if not node.identifier(sptr.id):
                    sptr = idaapi.get_member_struc(idaapi.get_member_fullname(mptr.id))

                # Validate that the type of the mptr is what we're expecting.
                if not isinstance(mptr, idaapi.member_t):
                    name = internal.utils.string.of(idaapi.get_member_fullname(xrfrom))
                    raise internal.exceptions.InvalidTypeOrValueError(u"{:s}.structure({:#x}) : Unexpected type {!s} returned for member \"{:s}\".".format('.'.join([__name__, cls.__name__]), this.id, mptr.__class__, internal.utils.string.escape(name, '"')))

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
                    raise internal.exceptions.FunctionNotFoundError(u"{:s}.structure({:#x}) : Unable to locate the function for frame member {:#x} by address {:#x}.".format('.'.join([__name__, cls.__name__]), this.id, mptr.id, ea))

                # If we couldn't grab the frame, then we bail on that too.
                elif not idaapi.get_frame(func):
                    raise internal.exceptions.MissingTypeOrAttribute(u"{:s}.structure({:#x})) : The function at {:#x} for frame member {:#x} does not have a frame.".format('.'.join([__name__, cls.__name__]), this.id, ea, mptr.id))

                # Otherwise we're referencing a frame member, and we need to figure out
                # the structure and the base that we'll be creating its structure at.
                else:
                    sptr, soffset = idaapi.get_frame(func), function.frame_offset(func)

                # Now we need to figure out the index of the member and then we can yield it.
                packed = sptr, mptr
                yield soffset, packed

            # If it's not code, then we're just a reference to an address and so we
            # need to yield the address it's for along with its reference type.
            elif not address.flags(xrfrom, idaapi.MS_CLS) == idaapi.FF_CODE:
                yield xrfrom, ref_t(xrfrom, reftype_t.of(xrtype))

            # If it's code, then we skip this because structure_t.up only returns
            # data references to the structure and operands are for structure_t.refs.
            else:
                logging.debug(u"{:s}.structure({:#x}) : Skipping {:s}({:d}) reference at {:#x} with the type ({:d}) due to the reference address not marked as data.".format('.'.join([__name__, cls.__name__]), this.id, 'code' if xriscode else 'data', xriscode, xrfrom, xrtype))
            continue
        return

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
    def has(cls, func, *ea):
        '''Return if the address `func` is within a function (not external) or contains the address `ea`.'''
        f = int(func)
        fn = idaapi.get_func(f)

        # If the function address is not a function, then return false.
        if not fn:
            return False

        # If the address is in an external segment, then it's not a function.
        elif idaapi.segtype(f) == idaapi.SEG_XTRN:
            return False

        # If we got here, we didn't hit any constraints which means that we must
        # be a function.
        elif not ea:
            return True

        # If we were given an address to check, get a list of the functions that
        # own it, and check if the function we were given is contained in them.
        entry, owners = range.start(fn), cls.owners(*map(int, ea))
        return entry in {ea for ea in owners}

    @classmethod
    def iterate(cls, *bounds):
        '''Yield the address for each function in the database within the specified `bounds`.'''
        [packed] = bounds if bounds else [address.bounds()]

        # unpack the parameter we were given into its start and end addresses.
        if hasattr(packed, 'bounds'):
            start, stop = sorted(packed.bounds)
        elif isinstance(packed, tuple):
            start, stop = sorted(packed)
        else:
            start, stop = sorted(range.unpack(packed))

        # find first function chunk by skipping over any chunk that is a tail.
        ch = idaapi.get_fchunk(start) or idaapi.get_next_fchunk(start)
        while ch and range.start(ch) < stop and (ch.flags & idaapi.FUNC_TAIL):
            ch = idaapi.get_next_fchunk(range.start(ch))

        # we have a non-tail chunk, so we can now iterate through the rest of
        # the functions within the boundaries we determined at the beginning.
        while ch and range.start(ch) < stop:
            if function.has(range.start(ch)):
                yield range.start(ch)
            ch = idaapi.get_next_func(range.start(ch))
        return

    @classmethod
    def enumerate(cls):
        '''Yield the index and address for each function within the database.'''
        quantity = idaapi.get_func_qty()

        # We can now use the quantity to iterate through all of the functions
        # within the functions list. Once we get the `idaapi.func_t`, we unpack
        # its starting address so we can yield it along with the function index.
        for index in builtins.range(0, max(quantity, -1) + 1):
            fn = idaapi.getn_func(index)
            if fn:
                yield index, range.start(fn)
            continue
        return

    @classmethod
    def ordinal(cls, ea):
        '''Return the ordinal for the function at the address `ea`.'''
        func = cls.by(ea)
        return idaapi.get_func_num(range.start(func))

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

    @classmethod
    def by(cls, func, **caller):
        '''Return the function that can be identified by `func`.'''
        if isinstance(func, idaapi.func_t):
            result = func
        elif isinstance(func, internal.types.integer) or hasattr(func, '__int__'):
            result = cls.by_address(int(func))
        elif isinstance(func, internal.types.string):
            result = cls.by_name(func)
        elif isinstance(func, (idaapi.struc_t, internal.structure.structure_t)):
            result = cls.by_frame(func if isinstance(func, idaapi.struc_t) else func.ptr)
        else:
            result = None

        # If any of our finders returned None, then raise an exception.
        if result is None:
            raise cls.missing(func, **caller)
        return result

    @internal.utils.multicase()
    @classmethod
    def missing(cls, **caller):
        '''Raise an exception related to the current location not containing a function.'''
        caller = caller.get('caller', [cls.__name__, 'by'])
        ea = idaapi.get_screen_ea()
        raise internal.exceptions.FunctionNotFoundError(u"{:s}({:#x}) : Unable to locate a function at the currently selected address ({:#x}).".format('.'.join(caller) if isinstance(caller, internal.types.list) else caller, ea, ea))
    @internal.utils.multicase(name=internal.types.string)
    @classmethod
    def missing(cls, name, **caller):
        '''Raise an exception related to the `name` not being found.'''
        caller = caller.get('caller', [cls.__name__, 'by'])
        raise internal.exceptions.FunctionNotFoundError(u"{:s}({!r}) : Unable to locate a function with the specified name ({!s}).".format('.'.join(caller) if isinstance(caller, internal.types.list) else caller, name, internal.utils.string.repr(name)))
    @internal.utils.multicase(ea=internal.types.integer)
    @classmethod
    def missing(cls, ea, **caller):
        '''Raise an exception related to the address in `ea` not pointing to a function.'''
        caller = caller.get('caller', [cls.__name__, 'by'])
        raise internal.exceptions.FunctionNotFoundError(u"{:s}({:#x}) : Unable to locate a function at the specified address ({:#x}).".format('.'.join(caller) if isinstance(caller, internal.types.list) else caller, ea, ea))
    @internal.utils.multicase(frame=idaapi.struc_t)
    @classmethod
    def missing(cls, frame, **caller):
        '''Raise an exception related to the structure in `frame` not being part of a function.'''
        caller = caller.get('caller', [cls.__name__, 'by'])
        name = internal.utils.string.of(idaapi.get_struc_name(frame.id))
        raise internal.exceptions.FunctionNotFoundError(u"{:s}({:#x}) : Unable to locate a function using a structure ({!s}) that is not a frame.".format('.'.join(caller) if isinstance(caller, internal.types.list) else caller, frame.id, internal.utils.string.repr(name)))
    @internal.utils.multicase()
    @classmethod
    def missing(cls, unsupported, **caller):
        '''Raise an exception due to receiving an `unsupported` type.'''
        caller = caller.get('caller', [cls.__name__, 'by'])
        raise internal.exceptions.FunctionNotFoundError(u"{:s}({!r}) : Unable to locate a function using an unsupported type ({!s}).".format('.'.join(caller) if isinstance(caller, internal.types.list) else caller, unsupported, internal.utils.pycompat.fullname(unsupported.__class__)))

    @classmethod
    def owners(cls, ea):
        '''Return a list of the functions that have ownership of the chunk at address `ea`.'''
        owner, chunk = idaapi.get_func(int(ea)), idaapi.get_fchunk(int(ea))

        # If there's no chunk or owner, then this isn't a function and we return an empty list.
        if owner is None or chunk is None:
            return []

        # If the chunk is not a FUNC_TAIL, then we just need to return the chunk owner.
        if not (chunk.flags & idaapi.FUNC_TAIL):
            return [range.start(owner)]

        # If this is a function tail, then we need to iterate through the referers
        # for the chunk so that we can yield each address. Older versions of IDA
        # don't always give us an array, so we construct it if we don't get one.
        count, iterator = chunk.refqty, idaapi.func_parent_iterator_t(chunk)

        # Try and seek to the very first member of the iterator. This should
        # always succeed, so if it errors out then this is critical...but only
        # if our "refqty" is larger than 1. If it's less than 1, then we can
        # just warn the user..but we're gonna fall back to the func_t anyways.
        if not iterator.first():
            if count > 1:
                raise internal.exceptions.DisassemblerError(u"{:s}.owners({:#x}) : Unable to seek to the first element of the `{:s}` for the function tail at {!s}.".format('.'.join([__name__, cls.__name__]), ea, internal.utils.pycompat.fullname(iterator.__class__), range.bounds(chunk)))

            # We should only have one single referrer to return. Just in case,
            # though, we return an empty list if our "refqty" is actually 0.
            logging.warning(u"{:s}.owners({:#x}) : Returning initial owner ({!s}) for the function tail at {!s} due to being unable to seek to the first element of the associated `{:s}`.".format('.'.join([__name__, cls.__name__]), ea, range.bounds(owner), range.bounds(chunk), internal.utils.pycompat.fullname(iterator.__class__)))
            referrers = [range.start(owner)] if count else []

        # Grab the first parent address. Afterwards we continue looping
        # whilst stashing parents in our list of referrers.
        else:
            referrers = [iterator.parent()]
            while iterator.next():
                item = iterator.parent()
                referrers.append(item)

        # That was easy enough, so now we just need to confirm that the
        # number of our referrers matches to the "refqty" of the chunk.
        if count != len(referrers):
            logging.warning(u"{:s}.owners({:#x}) : Expected to find {:d} referrer{:s} for the function tail at {!s}, but {:s}{:s} returned.".format('.'.join([__name__, cls.__name__]), ea, count, '' if count == 1 else 's', range.bounds(owner), 'only ' if len(referrers) < count else '', "{:d} was".format(len(referrers)) if len(referrers) == 1 else "{:d} were".format(len(referrers))))
        return referrers

    @classmethod
    def flags(cls, func, *mask):
        '''Return the flags for the function `func` selected with the specified `mask`.'''
        flags = func.flags
        if len(mask) < 2:
            return idaapi.as_uint32(operator.and_(flags, *mask) if mask else flags)

        # Set the flags for the function `func` selected by the specified `mask` to the provided `integer`.
        [mask, integer] = mask
        preserve, value = idaapi.as_uint32(~mask), idaapi.as_uint32(-1 if integer else 0) if isinstance(integer, internal.types.bool) else idaapi.as_uint32(integer)
        res, func.flags = func.flags, (func.flags & preserve) | (value & mask)
        return idaapi.as_uint32(res & mask) if idaapi.update_func(func) else None

    @classmethod
    def chunks(cls, func):
        '''Yield each chunk that is associated with the function `func`.'''
        fn = cls.by(func)
        fci = idaapi.func_tail_iterator_t(fn, range.start(fn))
        if not fci.main():
            raise internal.exceptions.DisassemblerError(u"{:s}.chunks({:#x}) : Unable to create an `{:s}` to iterate through the chunks for the given function.".format(__name__, range.start(fn), internal.utils.pycompat.fullname(idaapi.func_tail_iterator_t)))

        results = []
        while True:
            ch = fci.chunk()
            yield ch
            if not fci.next(): break
        return

    @classmethod
    def chunk(cls, func, ea):
        '''Return the chunk belonging the function `func` that resides at the address `ea`.'''
        ea = int(ea)
        for chunk in cls.chunks(func):
            left, right = range.unpack(chunk)
            if left <= ea < right:
                return range.pack(left, right)
            continue
        return

    @classmethod
    def enumerate_chunks(cls):
        '''Enumerate all of the function chunks within the database.'''
        quantity = idaapi.get_fchunk_qty()

        # Use the quantity to iterate through all of the chunks
        # in the database and yield whatever the api gave us.
        for index in builtins.range(0, max(quantity, -1) + 1):
            ch = idaapi.getn_fchunk(index)
            if ch:
                yield index, ch
            continue
        return

    @classmethod
    def chunk_ordinal(cls, ea):
        '''Return the index for the function chunk at the address `ea`.'''
        if isinstance(ea, internal.types.integer) or hasattr(ea, '__int__'):
            start, stop = int(ea), 0
        elif isinstance(ea, tuple):
            start, stop = ea.bounds if hasattr(ea, 'bounds') else ea
        else:
            start, stop = interface.range.unpack(ea)

        # Now we have an address that we can use to get the chunk.
        res = idaapi.get_fchunk_num(start)
        if res < 0:
            raise function.missing(ea)
        return res

    __skippable_name__ = '$ ignore micro'
    @classmethod
    def skippable(cls, boundaries):
        '''Yield the address and ignore code of each instruction that has been toggled as skippable from the list of `boundaries`.'''
        if not internal.netnode.has(cls.__skippable_name__):
            return (sup_val for sup_val in [])
        nidx = internal.netnode.get(cls.__skippable_name__)
        if isinstance(boundaries, (idaapi.func_t, internal.types.integer)):
            ranges = map(range.unpack, cls.chunks(boundaries))
        else:
            ranges = [bounds for bounds in boundaries]
        iterable = ((internal.netnode.sup.forward(nidx, idaapi.ea2node(start), type=bytes, tag=0), stop) for start, stop in ranges)
        iterators = [itertools.takewhile((lambda stop: lambda sup_val: sup_val[0] < stop)(stop), iterator) for iterator, stop in iterable]
        Fsup_val = lambda sup_val: (idaapi.node2ea(sup_val[0]), sup_val[1])
        return itertools.chain(*(internal.utils.imap(Fsup_val, iterator) for iterator in iterators))

    @classmethod
    def prologue(cls, func):
        '''Return a list of the addresses from the function `func` that belong to its prologue.'''
        range_t = idaapi.area_t if idaapi.__version__ < 7.0 else idaapi.range_t
        if isinstance(func, (idaapi.func_t, internal.types.integer)):
            list = map(range.unpack, cls.chunks(func))
        elif isinstance(func, (range_t, idaapi.BasicBlock)):
            list = [range.unpack(func)]
        else:
            list = func if isinstance(func, internal.types.list) else [func]
        iterable = cls.skippable(list)
        return [ea for ea, val in iterable if val == b'\x01']

    @classmethod
    def epilogue(cls, func):
        '''Return a list of the addresses from the function `func` that belong to its epilogue.'''
        range_t = idaapi.area_t if idaapi.__version__ < 7.0 else idaapi.range_t
        if isinstance(func, (idaapi.func_t, internal.types.integer)):
            list = map(range.unpack, cls.chunks(func))
        elif isinstance(func, (range_t, idaapi.BasicBlock)):
            list = [range.unpack(func)]
        else:
            list = func if isinstance(func, internal.types.list) else [func]
        iterable = cls.skippable(list)
        return [ea for ea, val in iterable if val == b'\x02']

    @classmethod
    def flowchart(cls, func, *flags):
        '''Return a ``FlowChart`` object built with the specified `flags` for the function `func`.'''
        fn = func if isinstance(func, idaapi.func_t) else cls.by(func)
        defaults = itertools.chain([idaapi.FC_PREDS, idaapi.FC_NOEXT], [idaapi.FC_CALL_ENDS] if hasattr(idaapi, 'FC_CALL_ENDS') else [])
        [flags_] = flags if flags else [functools.reduce(operator.or_, defaults)]
        return idaapi.FlowChart(f=fn, flags=flags_)

    @classmethod
    def blocks(cls, func, *flags):
        '''Yield each ``BasicBlock`` belonging to the function `func` with the specified `flags`.'''
        fn = func if isinstance(func, idaapi.func_t) else cls.by(func)

        # figure out the default flags to use if none were specified.
        defaults = itertools.chain([idaapi.FC_PREDS, idaapi.FC_NOEXT], [idaapi.FC_CALL_ENDS] if hasattr(idaapi, 'FC_CALL_ENDS') else [])
        FC_CALL_ENDS, has_calls = getattr(idaapi, 'FC_CALL_ENDS', 0x20), hasattr(idaapi, 'FC_CALL_ENDS')
        [flags] = flags if flags else [functools.reduce(operator.or_, defaults)]

        # build a tree that we can use to check if a point belongs to a chunk.
        chunks = sorted(range.unpack(chunk) for chunk in cls.chunks(fn))
        ranges, points = {}, [point for point in itertools.chain(*chunks)]
        [ranges.setdefault(left, (lambda left, right: lambda ea: left <= ea < right)(left, right)) for left, right in chunks]
        [ranges.setdefault(right, (lambda left, right: lambda ea: left <= ea < right)(left, right)) for left, right in chunks]
        inside = lambda ea: (lambda index: index and ranges[points[index - 1]](ea))(bisect.bisect_right(points, ea))

        # iterate through all the basic-blocks in the flow chart and yield
        # each of them back to the caller. we need to ensure that the bounds
        # are actually contained by the function, so we collect this too.
        for bb in cls.flowchart(func, flags):
            start, stop = range.unpack(bb)

            # if we're unable to split up calls, then we need to traverse
            # this block so that we can figure out where we need to split.
            if not has_calls and flags & FC_CALL_ENDS:
                locations = [ea for ea in address.items(start, stop) if instruction.is_call(ea)]

                # now that we've collected all of the locations of any
                # call instructions, we use them to yield each block.
                for ea in locations:
                    left, right = start, idaapi.next_not_tail(ea)
                    yield idaapi.BasicBlock(bb.id, range.pack(left, right), bb._fc)
                    start = right

                # if the addresses are different, then we have one more block to yield.
                if start < stop:
                    yield idaapi.BasicBlock(bb.id, range.pack(start, stop), bb._fc)

                # if they're the same and we didn't have to chop it up, then this is external.
                elif not(flags & idaapi.FC_NOEXT) and start == stop and not locations:
                    yield idaapi.BasicBlock(bb.id, range.pack(start, stop), bb._fc)
                continue

            # if we've been asked to return external blocks which might be outside
            # the selected function, then we can just yield the current block.
            elif not(flags & idaapi.FC_NOEXT):
                yield bb

            # otherwise, we verify that the block is inside a chunk before yielding it.
            elif start != stop and inside(start):
                yield bb
            continue
        return

    @classmethod
    def block(cls, func, ea, *flags):
        '''Return the ``BasicBlock`` at the address `ea` for the function `func` with the specified `flags`.'''
        fn = func if isinstance(func, idaapi.func_t) else cls.by(func)
        for bb in cls.blocks(fn, *flags):
            if range.within(ea, bb):
                return bb
            continue
        raise internal.exceptions.AddressNotFoundError(u"{:s}.at({:#x}, {:#x}{:s}) : Unable to locate `{:s}` for address {:#x} in the specified function ({:#x}).".format('.'.join([__name__, cls.__name__]), range.start(fn), ea, ", {:#x}".format(*flags) if flags else '', internal.utils.pycompat.fullname(idaapi.BasicBlock), ea, range.start(fn)))

    @classmethod
    def frame_offset(cls, func, *offset):
        '''Return the base offset used by the frame belonging to the function `func`.'''
        fn = func if isinstance(func, idaapi.func_t) or func is None else cls.by(func)
        res = 0 if fn is None or fn.frame == idaapi.BADNODE else -idaapi.frame_off_args(fn) + idaapi.get_frame_retsize(fn)
        return operator.add(res, *map(int, offset)) if offset else res

    @classmethod
    def frame_disassembler_offset(cls, func, *offset):
        '''Return the disassembler offset used by the frame belonging to the function `func`.'''
        fn = func if isinstance(func, idaapi.func_t) or func is None else cls.by(func)
        res = 0 if fn is None or fn.frame == idaapi.BADNODE else -fn.frsize
        return operator.add(res, *map(int, offset)) if offset else res

    @classmethod
    def frame_member_offset(cls, func, offset):
        '''Return the offset used by the member name at the specified `offset` of the frame belonging to the function `func`.'''
        fn = func if isinstance(func, idaapi.func_t) or func is None else cls.by(func)
        vars, retaddr, args = idaapi.frame_off_savregs(fn), idaapi.frame_off_retaddr(fn), idaapi.frame_off_args(fn)
        return cls.frame_disassembler_offset(fn, offset) if offset < retaddr else offset - args if args <= offset else 0

    @classmethod
    def frame_registers(cls, func):
        '''Return the size of the preserved registers in the frame belonging to the function `func`.'''
        fn = func if isinstance(func, idaapi.func_t) or func is None else cls.by(func)
        return fn.frregs + idaapi.get_frame_retsize(fn) if fn else 0

    @classmethod
    def frame_pointer_delta(cls, func, *delta):
        '''Return the size of the frame pointer delta belonging to the function `func`.'''
        fn = func if isinstance(func, idaapi.func_t) else cls.by(func)
        if delta and not idaapi.update_fpd(fn, *map(int, delta)):
            raise internal.exceptions.DisassemblerError(u"{:s}.frame_pointer_delta({:#x}, {:s}) : Unable to update the frame pointer delta for the specified function ({:#x}).".format('.'.join([__name__, cls.__name__]), range.start(fn), "{:+#x}".format(*map(int, delta)), range.start(fn)))
        return fn.fpd

    @classmethod
    def frame(cls, func, *offset):
        '''Return the frame belonging to the function `func`.'''
        fn = func if isinstance(func, idaapi.func_t) else cls.by(func)
        sptr = idaapi.get_frame(fn)
        if fn.frame == idaapi.BADNODE or not sptr:
            raise internal.exceptions.MissingTypeOrAttribute(u"{:s}.frame({:#x}) : The specified function does not have a frame.".format('.'.join([__name__, cls.__name__]), range.start(fn)))
        base = itertools.chain(offset, [0])
        return internal.structure.new(sptr.id, cls.frame_offset(fn) + next(base))

    @classmethod
    def name(cls, func):
        '''Return the unmangled name of the function at `func`.'''
        utils, get_name = internal.utils, functools.partial(idaapi.get_name, idaapi.BADADDR) if idaapi.__version__ < 7.0 else idaapi.get_name
        MANGLED_CODE, MANGLED_DATA, MANGLED_UNKNOWN = getattr(idaapi, 'MANGLED_CODE', 0), getattr(idaapi, 'MANGLED_DATA', 1), getattr(idaapi, 'MANGLED_UNKNOWN', 2)
        Fmangled_type = idaapi.get_mangled_name_type if hasattr(idaapi, 'get_mangled_name_type') else utils.fcompose(utils.frpartial(idaapi.demangle_name, 0), utils.fcondition(operator.truth)(0, MANGLED_UNKNOWN))
        MNG_LONG_FORM = getattr(idaapi, 'MNG_LONG_FORM', 0x6400007)

        # check to see if it's a runtime-linked function
        rt, ea = addressOfRuntimeOrStatic(func)
        if rt:
            name = get_name(ea)
            mangled_name_type_t = Fmangled_type(name)
            return utils.string.of(name) if mangled_name_type_t == MANGLED_UNKNOWN else utils.string.of(idaapi.demangle_name(name, MNG_LONG_FORM) or name)

        # otherwise it's a regular function, so try and get its name in a couple of ways
        name = idaapi.get_func_name(ea)
        if not name: name = get_name(ea)
        if not name: name = idaapi.get_true_name(ea, ea) if idaapi.__version__ < 6.8 else idaapi.get_ea_name(ea, idaapi.GN_VISIBLE)

        # decode the string from IDA's UTF-8 and demangle it if we need to
        # XXX: how does demangling work with utf-8? this would be implementation specific, no?
        mangled_name_type_t = Fmangled_type(name)
        return utils.string.of(name) if mangled_name_type_t == MANGLED_UNKNOWN else utils.string.of(idaapi.demangle_name(name, MNG_LONG_FORM) or name)

    @classmethod
    def color(cls, func, *rgb):
        '''Get the color (RGB) of the function `func` or set it to the color given by `rgb`.'''
        original, DEFCOLOR, ok = func.color, 0xffffffff, True
        fn = func if isinstance(func, idaapi.func_t) else cls.by(func)

        # Set the color (RGB) of the function `func` to `rgb`.
        if rgb:
            r, b = (operator.and_(0xff * shift, *rgb) // shift for shift in [0x010000, 0x000001])
            fn.color = DEFCOLOR if operator.contains({None, DEFCOLOR}, *rgb) else sum([b * 0x010000, operator.and_(0x00ff00, *rgb), r * 0x000001])
            ok = idaapi.update_func(fn)

        # Return the original color (BGR) with its order set to to RGB.
        b, r = (operator.and_(0xff * shift, original) // shift for shift in [0x010000, 0x000001])
        if ok:
            return original if original == DEFCOLOR else sum([0x010000 * r, 0x00ff00 & original, 0x000001 * b])
        return

    @classmethod
    def blockcolor(cls, bb, *rgb, **frame):
        '''Get the background color (RGB) belonging to the basic block at `bb` or set it to the color given by `rgb`.'''
        get_node_info, set_node_info, clr_node_info = (idaapi.get_node_info2, idaapi.set_node_info2, idaapi.clr_node_info2) if idaapi.__version__ < 7.0 else (idaapi.get_node_info, idaapi.set_node_info, idaapi.clr_node_info)
        DEFCOLOR, framecolorQ = 0xffffffff, operator.contains(frame, 'frame') and (not isinstance(frame['frame'], internal.types.bool) or (rgb and 'frame' in frame))

        # Grab the node information and the color from its attributes.
        fn, ni = cls.by(range.start(bb)), idaapi.node_info_t()
        ok = get_node_info(ni, range.start(fn), bb.id) or 0 <= bb.id < bb._fc.size
        ea, original = range.start(fn), ni.frame_color if frame.get('frame', framecolorQ) else ni.bg_color
        if not ok: return

        # Set the colors (RGB) of the basic block at `bb` to `rgb`.
        [framergb] = frame.values() if isinstance(frame.get('frame', None), internal.types.integer) else rgb if rgb else [None]
        if rgb and framecolorQ and isinstance(framergb, internal.types.integer):
            [blockrgb], original, flags = rgb, ni.bg_color, idaapi.NIF_BG_COLOR | idaapi.NIF_FRAME_COLOR

            # Assign the necessary attributes to apply the chosen colors.
            r, b = (operator.and_(0xff * shift, blockrgb) // shift for shift in [0x010000, 0x000001])
            ni.bg_color = DEFCOLOR if blockrgb == DEFCOLOR else sum([b * 0x010000, 0x00ff00 & blockrgb, r * 0x000001])
            r, b = (operator.and_(0xff * shift, framergb) // shift for shift in [0x010000, 0x000001])
            ni.frame_color = DEFCOLOR if framergb == DEFCOLOR else sum([b * 0x010000, 0x00ff00 & framergb, r * 0x000001])
            (set_node_info(ea, bb.id, ni, flags), clr_node_info(ea, bb.id, flags)) if (blockrgb, framergb) == (DEFCOLOR, DEFCOLOR) else set_node_info(ea, bb.id, ni, flags)

        # Set the frame color (RGB) of the basic block at `bb` to `rgb`.
        elif framecolorQ:
            blockrgb, original, flags = framergb, ni.frame_color, idaapi.NIF_FRAME_COLOR
            r, b = (operator.and_(0xff * shift, blockrgb) // shift for shift in [0x010000, 0x000001])
            ni.frame_color = blockrgb if blockrgb == DEFCOLOR else sum([b * 0x010000, 0x00ff00 & blockrgb, r * 0x000001])
            (set_node_info(ea, bb.id, ni, flags), clr_node_info(ea, bb.id, flags)) if blockrgb == DEFCOLOR else set_node_info(ea, bb.id, ni, flags)

        # Set the background color (RGB) of the basic block at `bb` to `rgb`.
        elif rgb and not framecolorQ:
            [blockrgb], original, flags = rgb, ni.bg_color, idaapi.NIF_BG_COLOR
            r, b = (operator.and_(0xff * shift, blockrgb) // shift for shift in [0x010000, 0x000001])
            ni.bg_color = blockrgb if blockrgb == DEFCOLOR else sum([b * 0x010000, 0x00ff00 & blockrgb, r * 0x000001])
            (set_node_info(ea, bb.id, ni, flags), clr_node_info(ea, bb.id, flags)) if blockrgb == DEFCOLOR else set_node_info(ea, bb.id, ni, flags)

        # Otherwise, we were given a non-integer and we simply ignore the stupidity.
        elif rgb:
            assert(framecolorQ and not isinstance(framergb, internal.types.integer))

        # Refresh the view if we updated any of the block's colors.
        if rgb or framecolorQ:
            idaapi.refresh_idaview_anyway()

        # Return the original color (RGB) of the basic block at `bb`.
        b, r = (operator.and_(0xff * shift, original) // shift for shift in [0x010000, 0x000001])
        return original if original == DEFCOLOR else sum([0x010000 * r, 0x00ff00 & original, 0x000001 * b])

    @classmethod
    def has_typeinfo(cls, func):
        '''Return a boolean describing whether the function `func` has a prototype associated with it.'''
        get_tinfo = (lambda ti, ea: idaapi.get_tinfo2(ea, ti)) if idaapi.__version__ < 7.0 else idaapi.get_tinfo
        guess_tinfo = (lambda ti, ea: idaapi.guess_tinfo2(ea, ti)) if idaapi.__version__ < 7.0 else idaapi.guess_tinfo
        _, ea = addressOfRuntimeOrStatic(func)

        # If we're able to straight-up get the type information for a function or guess it, then we're good.
        ti = idaapi.tinfo_t()
        ok = get_tinfo(ti, ea) or guess_tinfo(ti, ea) == idaapi.GUESS_FUNC_OK
        return True if ok else False

    @classmethod
    def typeinfo(cls, func):
        '''Return the type information for the function `func`.'''
        get_tinfo = (lambda ti, ea: idaapi.get_tinfo2(ea, ti)) if idaapi.__version__ < 7.0 else idaapi.get_tinfo
        guess_tinfo = (lambda ti, ea: idaapi.guess_tinfo2(ea, ti)) if idaapi.__version__ < 7.0 else idaapi.guess_tinfo
        rt, ea = addressOfRuntimeOrStatic(func)

        # Try to get the type information for the function or guess it if we couldn't.
        ti = idaapi.tinfo_t()
        res = get_tinfo(ti, ea) or guess_tinfo(ti, ea)

        # If our result is not equal to GUESS_FUNC_FAILED (get_tinfo returns True, then we're good.
        if res != idaapi.GUESS_FUNC_FAILED:
            return tinfo.concretize(ti)

        # If that didn't work, then we lie about it, because we should always be able to return a type.
        logging.debug(u"{:s}({:#x}) : Ignoring failure code ({:d}) when trying to guess the `{:s}` for the specified function.".format('.'.join([__name__, cls.__name__]), ea, res, ti.__class__.__name__))

        # Guess the default int size by checking the size of a pointer. It's pretty
        # likely this is a terrible way to determine the size of a default result.
        tif = idaapi.tinfo_t()
        tif.create_ptr(idaapi.tinfo_t(idaapi.BT_VOID))
        deftype = {1: idaapi.BT_INT8, 2: idaapi.BT_INT16, 4: idaapi.BT_INT, 8: idaapi.BT_INT64}.get(tif.get_size(), idaapi.BT_INT)
        int = idaapi.tinfo_t(deftype)

        # FIXME: Figure out if the decompiler determines the default integer from something
        #        other than the register size used by a result. I couldn't find anything
        #        inside the compiler_info_t, so maybe there's something inside processor_t?

        # Instead of assuming stdcall for rt-linked and cdecl for in-module functions (not always
        # true), use the unknown calling convention which seems to appear as the compiler default.
        ftd = idaapi.func_type_data_t()
        ftd.rettype, ftd.cc = int, functools.reduce(operator.or_, [getattr(idaapi, attribute, value) for attribute, value in [('CM_CC_UNKNOWN', 0x10), ('CM_M_NN', 0), ('CM_UNKNOWN', 0)]])
        return tinfo.concretize(ti) if ti.create_func(ftd) else None

    @classmethod
    def pointer(cls, info):
        '''Promote the type information specified as `info` to a function pointer if necessary.'''
        if any([info.is_ptr(), info.is_func()]):
            return info

        # If it's not a pointer then we need to promote it.
        ti = idaapi.tinfo_t()
        pi = idaapi.ptr_type_data_t()
        pi.obj_type = info
        return ti if ti.create_ptr(pi) else None

    @classmethod
    def apply_typeinfo(cls, ea, info, *flags):
        '''Apply the type information in `info` to the function at the address `ea` with the given `flags`'''
        _, fn = addressOfRuntimeOrStatic(ea)
        callers = [ref for ref in xref.to_code(fn) if idaapi.get_func(ref) and instruction.is_call(ref)]
        ranges, marks = [(ref, idaapi.next_not_tail(ref)) for ref in callers], [idaapi.AU_USED, idaapi.AU_TYPE]
        originalnames, has_ranged_wait = tinfo.names(info) if info else [], hasattr(idaapi, 'auto_make_step') or hasattr(idaapi, 'auto_wait_range')

        # Now that we've pre-enumerated our callers, we need a second variation
        # of the given type so that we can avoid the PIT machinery propagating
        # the names throughout the database. This way no field names are changed
        # outside of the function without the user explicitly specifying it.
        nameless = tinfo.names(info, [''] * len(originalnames)) if originalnames else info

        # Now that we've pre-enumerated our callers, we can apply the type information from the
        # caller. We want to apply the user's type with the names excluded, so that the names
        # do not get propagated. Later, we'll then apply the type with its names included.
        ok = address.apply_typeinfo(fn, nameless if has_ranged_wait else info, *flags)

        # Next we try to single-step each update within the callers..using the best
        # api that is available. If it's not available, then we essentially abort.
        if hasattr(idaapi, 'auto_make_step'):
            [[idaapi.auto_make_step(*range) for range in ranges] for queue in marks]
        elif hasattr(idaapi, 'auto_wait_range'):
            [idaapi.auto_wait_range(*range) for range in ranges]

        # If we successfully applied the type, then the disassembler should have propagated
        # the parameters to all of the callers. Now we set the type with names to the address.
        set_tinfo = idaapi.set_tinfo2 if idaapi.__version__ < 7.0 else idaapi.set_tinfo
        if info and ok and not set_tinfo(ea, info):
            return False

        # We need to immediately unmark AU_TYPE and AU_USED after setting it, since when we
        # use set_tinfo, the disassembler doesn't wait until the database is updated. This
        # way we complete our original goal of avoiding the parameter names being propagated.
        if ok and info and has_ranged_wait:
            [[idaapi.auto_unmark(*range + (queue,)) for queue in marks] for range in ranges]
        return ok

    @classmethod
    def points(cls, func, ea):
        '''Yield the `(address, delta)` for each stack point from the chunk containing the address `ea` in the function `func`.'''
        fn, ch = cls.by(func), idaapi.get_fchunk(ea)

        # If we were unable to get the function chunk for the provided address,
        # then (obviously) there aren't any stack deltas for what was requested.
        if ch is None:
            return

        # If this is a function tail, then we need to use the function we got
        # to filter out just the desired addresses and get their stackpoints.
        if ch.flags & idaapi.FUNC_TAIL and hasattr(getattr(fn, 'points', None), '__getitem__'):
            Fcontains, owner = range.bounds(ch).contains, fn

            # Now all we need to do is to grab all of the stack points for
            # the function, and filter them by our chunk's boundaries.
            points = (owner.points[index] for index in builtins.range(owner.pntqty))
            iterable = ((point.ea, point.spd) for point in points if Fcontains(point.ea))

        # A non-tail just requires us to iterate through the points stored in the
        # chunk, so we can yield the address and delta for each individual point.
        elif hasattr(ch, 'points') and hasattr(ch.points, '__getitem__'):
            points = (ch.points[index] for index in builtins.range(ch.pntqty))
            iterable = ((point.ea, point.spd) for point in points)

        # If we were completely unable to access the correct attributes, then we
        # need to do all of the work ourselves. We walk the entire function, filter
        # for deltas in our chunk, sort them, and then yield each of them one-by-one.
        else:
            spd, points = 0, {}
            for start, stop in map(range.unpack, cls.chunks(fn)):
                for ea in address.items(start, stop):
                    if address.flags(ea, idaapi.MS_CLS) != idaapi.FF_CODE:
                        continue

                    res = idaapi.get_spd(fn, ea)
                    if res != spd:
                        points[ea] = spd = res
                    continue
                continue

            filtered = filter(range.bounds(ch).contains, points)
            iterable = ((ea, points[ea]) for ea in sorted(filtered))

        # We have our iterator of points, so all we need to do is to unpack each
        # one and yield it to our caller.
        for ea, spd in iterable:
            yield ea, spd
        return

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

    def __same__(self, other):
        return isinstance(other, bounds_t)

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
        translate = (size * count, size * sign) if count < 0 else (0, -size + math.trunc(size * count))
        return self.__class__(*itertools.starmap(operator.add, zip(self, translate)))
    __rmul__ = __mul__

    def __lshift__(self, count):
        '''Shift the boundary `count` times to a lower address.'''
        return self.__pow__(-count)

    def __rshift__(self, count):
        '''Shift the boundary `count` times to a higher address.'''
        return self.__pow__(+count)

    def __pow__(self, index):
        '''Return the boundary translated to the specified `index` of an array.'''
        left, right = self
        size = right - left if left < right else left - right
        translate = functools.partial(operator.add, math.trunc(self.size * index))
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
        bytes, extra = divmod(bits, 8)
        return 1 + bytes if extra else bytes

    @property
    def type(self):
        '''Return the pythonic type of the current register part.'''
        _, _, bits = self
        bytes, extra = divmod(bits, 8)
        return builtins.int, 1 + bytes if extra else bytes

    @property
    def bytes(self):
        '''Return the bytes that make up the value of the current register part.'''
        register, position, bits = self
        count, extra = divmod(bits, 8)
        index, size = position // 8, 1 + count if extra else count
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

    def __format__(self, spec):
        '''Return the current location as a string containing the offset and its size.'''
        if spec != 's':
            cls = self.__class__
            raise TypeError(u"unsupported format string ({!s}) passed to {:s}".format(spec, '.'.join([cls.__name__, '__format__'])))
        offset, size = self
        return "{:#x}{:+d}".format(offset, size)

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
        if count < 0:
            offset, res = int(offset), math.trunc(size * count)
            return self.__class__(offset + res, abs(res) + size)
        res = math.trunc(size * count)
        return self.__class__(offset, res)
    __rmul__ = __mul__

    def __lshift__(self, count):
        '''Shift the location `count` times to a lower address.'''
        return self.__pow__(-count)

    def __rshift__(self, count):
        '''Shift the location `count` times to a higher address.'''
        return self.__pow__(+count)

    def __pow__(self, index):
        '''Return the boundary translated to the specified `index` of an array.'''
        offset, size = self
        return self.__class__(int(offset) + math.trunc(size * index), size)

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
    def integers(cls, dtype, bytes, **byteorder):
        '''Decode `bytes` into an array of integers that are of the specified `dtype`.'''
        order = cls.byteorder(**byteorder)

        # If the dtype is not associated with a typecode supported by the _array
        # module, then we need to do the decoding ourselves. We start by figuring
        # whether we're a float or an integer to figure out the correct decoder.
        if dtype & idaapi.DT_TYPE not in cls.integer_typecode:
            decode = cls.float if dtype & idaapi.DT_TYPE in {idaapi.FF_FLOAT, idaapi.FF_DOUBLE} else cls.signed if dtype & idaapi.FF_SIGN else cls.unsigned
            items = cls.list(cls.length_table[dtype & idaapi.DT_TYPE], bytes)
            reordered = [item if order == 'big' else item[::-1] for item in items]
            return [decode(item) for item in reordered]

        # Figure out the typecode and use it to create an _array. We will then use
        # this to do our decoding and then return it back to the caller.
        typecode = cls.integer_typecode[dtype & idaapi.DT_TYPE]
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

        # Now we can use the bytes we were given to initialize the _array,
        # flip it according to the byteorder, and then return it to the user.
        result.fromstring(builtins.bytes(bytes)) if sys.version_info.major < 3 else result.frombytes(bytes)
        result if order == sys.byteorder else result.byteswap()
        return result

    @classmethod
    def string(cls, width, bytes, **byteorder):
        '''Decode the provided `bytes` as an array containing characters of the specified `width`.'''
        order = cls.byteorder(**byteorder)
        typecode = cls.string_typecode[width]
        result = _array.array(typecode)
        mask = result.itemsize - 1
        if result.itemsize and len(bytes) % result.itemsize:
            extra = len(bytes) & mask
            logging.warning(u"{:s}.string({:d}, ...) : The amount of data available ({:#x}) for decoding is not a multiple of the requested character width ({:d}) and will result in discarding {:+d} byte{:s} when decoding the string.".format('.'.join([__name__, cls.__name__]), width, len(bytes), result.itemsize, extra, '' if extra == 1 else 's'))
            bytes = bytes[:-extra] if extra else bytes

        # Now we can load our array with the bytes we were given, flip the array
        # if the byteorder needs us to, and then return it to the caller.
        result.fromstring(builtins.bytes(bytes)) if sys.version_info.major < 3 else result.frombytes(bytes)
        result if order == sys.byteorder else result.byteswap()
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

        # Extract the byteorder from the keywords and use it to generate a callable
        # for flipping the bytes to correspond to the requested byteorder.
        order = cls.byteorder(**byteorder)
        Fordered = (lambda length, data: data) if order.lower() == 'big' else (lambda length, data: functools.reduce(operator.add, (item[::-1] for item in cls.list(length, data))) if data else data)

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
                result[name] = cls.float(Fordered(length, mdata)) if length == len(mdata) else cls.integers(dtype, mdata, order=order) or bytes(mdata)

            # Decoding references which could be an arbitrary size, but still need to be resolvable to an address.
            elif info and dtype & idaapi.MS_0TYPE == idaapi.FF_0OFF or dtype & idaapi.MS_1TYPE == idaapi.FF_1OFF:
                offsets = cls.array(mptr.flag, info, mdata, order=order)
                result[name] = offsets if len(offsets) > 1 else offsets[0] if offsets else bytes(mdata)

            # Otherwise, we can just decode everything using whatever flags were assigned to it.
            else:
                length = cls.length_table[dsize]
                result[name] = cls.unsigned(Fordered(length, mdata)) if length == len(mdata) else cls.integers(mptr.flag, mdata, order=order) or bytes(mdata)
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

        # Extract the byteorder from the keywords and use it to generate a callable
        # for flipping the bytes to correspond to the requested byteorder.
        order = cls.byteorder(**byteorder)
        Fordered = (lambda length, data: data) if order.lower() == 'big' else (lambda length, data: functools.reduce(operator.add, (item[::-1] for item in cls.list(length, data))) if data else data)

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
            prefix, array = cls.unsigned(Fordered(length, ldata)), cls.string(width, strdata, order=order)
            if length and prefix != len(array):
                logging.warning(u"{:s}.array({:#x}, {!s}, ...{:s}) : The string that was decoded had a length ({:d}) that did not match the length stored as the prefix ({:d}).".format('.'.join([__name__, cls.__name__]), flags, "{:#x}".format(info.strtype) if info else info, ", {:s}".format(internal.utils.string.kwargs(byteorder)) if byteorder else '', length, prefix))
            return array

        # Decoding references which can be of an arbitrary size, but need to be converted to an address.
        elif info and dtype & idaapi.MS_0TYPE == idaapi.FF_0OFF or dtype & idaapi.MS_1TYPE == idaapi.FF_1OFF:
            length, items = cls.length_table[dsize], cls.integers(dtype, bytes, order=order)

            # FIXME: We should also support the REF_LOW8, REF_LOW16, REF_HIGH8,
            #        and REF_HIGH16 reference types. Unfortunately, I'm not sure
            #        about the correct way to do this. So instead, if the type
            #        is not REF_OFF8, REF_OFF16, REF_OFF32, or REF_OFF64 then we
            #        use the element size (length) from the flags.. ignoring
            #        the reference type entirely.

            # This dictionary is used to determine the length for the reference
            # type so that we can calculate a mask to apply to each integer.
            rilength = {idaapi.REF_OFF8: 1, idaapi.REF_OFF16: 2, idaapi.REF_OFF32: 4, idaapi.REF_OFF64: 8}

            # FIXME: I'm pretty sure that I'm not correctly processing the flags
            #        since we're not supporting things like REFINFO_SELFREF or
            #        REFINFO_NOBASE. This would be useful to have, but I just
            #        haven't yet encountered a need for the other reftypes.
            ritype, riflags = info.ri.flags & idaapi.REFINFO_TYPE, info.ri.flags

            # If the reference info is signed, then take our items and convert them to fit within
            # the reference type size. Unfortunately, the idaapi.as_signed function doesn't clamp
            # its integer unless it has its signed bit set, so we need to clamp that ourselves.
            if riflags & idaapi.REFINFO_SIGNEDOP and ritype in {idaapi.REF_OFF8, idaapi.REF_OFF16, idaapi.REF_OFF32, idaapi.REF_OFF64}:
                mask = pow(2, 8 * length) - 1
                signed = (idaapi.as_signed(item, 8 * length) for item in items)
                clamped = (item if item < 0 else item & mask for item in signed)

            # If it's unsigned, then we just need to figure out which mask to
            # use, and then we can apply it to each decoded integer.
            elif ritype in {idaapi.REF_OFF8, idaapi.REF_OFF16, idaapi.REF_OFF32, idaapi.REF_OFF64}:
                mask = pow(2, 8 * rilength[ritype]) - 1
                clamped = (item & mask for item in items)

            # Otherwise, we use the items in their unsigned form and clamp them to the reference type.
            else:
                mask = pow(2, 8 * length) - 1
                clamped = (item & mask for item in items)

            # Figure out which base to use for the refinfo_t. We only use the
            # base if it's valid. If it isn't, and REFINFO_RVAOFF is set, then
            # we use the imagebase. Otherwise we just fall back to 0.
            refbase = 0 if info.ri.base == idaapi.BADADDR else info.ri.base
            ribase = database.imagebase() if not refbase and riflags & idaapi.REFINFO_RVAOFF else refbase

            # XXX: The following is commented out because as far as I can tell,
            #      the REFINFO_SUBTRACT flag doesn't actually affect the
            #      reference target that gets displayed in the disassembler.

            # Figure out whether we add or subtract the base from the target.
            # op = functools.partial(operator.sub, ribase) if riflags & idaapi.REFINFO_SUBTRACT and ribase == info.ri.base else functools.partial(operator.add, ribase)

            # Now we can translate each item according to the reference info
            # delta and then return the result.
            op = functools.partial(operator.add, ribase)
            translated = (op(item + info.ri.tdelta) for item in clamped)
            return [ea for ea in translated]

        # Otherwise, we can just decode everything using whatever flags we got for it.
        length = cls.length_table[dsize]
        return cls.integers(flags, bytes, order=order)

class name(object):
    """
    This namespace provides tools that interact with the names in
    a database. This implies validating and transforming a name so
    that it can be applied to a particular address/identifier or
    checking if the name already exists within the database.
    """

    __long_formats__ = {None : u"{:s}::{:s}".format}
    __long_formats__.update({filetype : u"{:s}!{:s}".format for filetype in [
        idaapi.f_EXE_old, idaapi.f_COM_old, idaapi.f_DRV,
        idaapi.f_WIN, idaapi.f_LX, idaapi.f_LE, idaapi.f_COFF,
        idaapi.f_PE, idaapi.f_EXE, idaapi.f_COM,
    ]})
    __long_formats__.setdefault(idaapi.f_MACHO, u"{:s}`{:s}".format) if hasattr(idaapi, 'f_MACHO') else ()

    @classmethod
    def format_long(cls, module, name, *ordinal):
        '''Format the `module`, `name`, and `ordinal` components of symbol name for the current platform and return it.'''
        default_formatter = cls.__long_formats__[None]
        long_formatter = cls.__long_formats__.get(database.filetype(), default_formatter)

        # If the module is empty, then this will typically only
        # happen with gnu things. We can extract it from the end.
        if module is None and u'@@' in name:
            nestedname, nestedmodule = name.rsplit(u'@@', 1)
            return long_formatter(nestedmodule, nestedname)

        # Ordinal only makes sense on windows and it gets used if the
        # name is empty. We just assume Windows if it's at all empty.
        elif not name:
            name = u"Ordinal{:d}".format(*ordinal) if ordinal else ''
        return long_formatter(module, name) if all([module, name]) else ''

    @classmethod
    def exists(cls, name, *suffix):
        '''Return if the given `name` already exists at an address within the database.'''
        fullname = tuplename(name, *suffix)
        res, ea = idaapi.get_name_value(idaapi.BADADDR, internal.utils.string.to(fullname))
        return res != idaapi.NT_NONE

    @classmethod
    def inside(cls, ea, name, *suffix):
        '''Return if the given `name` already exists within the scope of address `ea`.'''
        fullname = tuplename(name, *suffix)
        res, ea = idaapi.get_name_value(ea, internal.utils.string.to(fullname))
        return res != idaapi.NT_NONE

    @classmethod
    def used(cls, name, *suffix):
        '''Return if the given `name` is used somewhere within the database.'''
        fullname = tuplename(name, *suffix)
        return internal.netnode.has(fullname)

    @classmethod
    def identifier(cls, name, *suffix):
        '''Transform the given `name` to the required characters for an identifier and return it.'''
        fullname = tuplename(name, *suffix) or '_'
        validated = idaapi.validate_name2(internal.utils.string.to(fullname)) if idaapi.__version__ < 7.0 else idaapi.validate_name(internal.utils.string.to(fullname), idaapi.SN_IDBENC)
        return internal.utils.string.of(validated)

    @classmethod
    def type(cls, name, *suffix):
        '''Transform the given `name` to the required characters for a type and return it.'''
        fullname = internal.utils.string.to(tuplename(name, *suffix) or '_')
        validated = idaapi.validate_name2(fullname) if idaapi.__version__ < 7.0 else idaapi.validate_name(fullname, idaapi.SN_IDBENC)
        if validated:
            return internal.utils.string.of(validated)

        # If the name could not be validated, then we need to manually fix the name because we
        # need to always return something. We test the characters individually since testing
        # slices of the string and leaning on is_valid_typename would pretty much be factorial time.
        res = ''.join(fullname[index : index + 1] if idaapi.is_valid_typename('_' + fullname[index : index + 1]) else '_' for index in builtins.range(len(fullname)))
        return internal.utils.string.of(res)

    @classmethod
    def member(cls, name, *suffix):
        '''Transform the given `name` to the required characters for a member and return it.'''
        fullname = tuplename(name, *suffix) or '_'
        validated = idaapi.validate_name2(internal.utils.string.to(fullname)) if idaapi.__version__ < 7.0 else idaapi.validate_name(internal.utils.string.to(fullname), idaapi.SN_IDBENC)
        return internal.utils.string.of(validated)

    @classmethod
    @internal.utils.string.decorate_arguments('string')
    def mangled(cls, ea, string):
        '''Return the type of the mangled `string` at the address `ea` as their corresponding flags.'''
        MANGLED_CODE, MANGLED_DATA, MANGLED_UNKNOWN = getattr(idaapi, 'MANGLED_CODE', 0), getattr(idaapi, 'MANGLED_DATA', 1), getattr(idaapi, 'MANGLED_UNKNOWN', 2)

        # Get the mangled name type using the string...since that's all we need.
        if hasattr(idaapi, 'get_mangled_name_type'):
            mangled_t = idaapi.get_mangled_name_type(internal.utils.string.to(string))

        # If we're using an older version of IDAPython, then get_mangled_name_type is not
        # exported and so we literally have no choice but to make an assumption.
        else:
            default = MANGLED_CODE if address.flags(ea, idaapi.MS_CLS) == idaapi.FF_CODE else MANGLED_DATA
            Fmangled_type = internal.utils.fcompose(internal.utils.frpartial(idaapi.demangle_name, idaapi.cvar.inf.long_demnames), internal.utils.fcondition(operator.truth)(default, MANGLED_UNKNOWN))
            mangled_t = Fmangled_type(string)

        # We convert the mangled_t into the flags (FF_CODE or FF_DATA) or 0 if it's not mangled.
        return {MANGLED_CODE: idaapi.FF_CODE, MANGLED_DATA: idaapi.FF_DATA, MANGLED_UNKNOWN: idaapi.FF_UNK}.get(mangled_t, idaapi.FF_UNK)

    @classmethod
    @contextlib.contextmanager
    def typename(cls, ordinal, library, name=None):
        '''Return a context manager that renames the type at the specified `ordinal` in `library` with a temporary `name` on entry and restores it on exit.'''
        Funique_name = internal.utils.fcompose(hash, functools.partial(operator.and_, sys.maxsize), functools.partial("{:s}_{:x}_{:x}".format, 'ti_unique', ordinal))

        # loop indefinitely until we get a name that is unique to the type library.
        temporary = name or Funique_name(hash("{:b}".format(ordinal)))
        while not temporary or idaapi.get_type_ordinal(library, temporary):
            temporary = Funique_name(temporary)

        # get the name and type by ordinal so that we can temporarily replace them.
        original = idaapi.get_numbered_type_name(library, ordinal)
        serialized = tinfo.get_numbered_type(library, ordinal)

        # if we were able to get the type, then replace it with our temporary name. if we
        # failed at either, then we assign an error code which will result in non-action.
        res = idaapi.set_numbered_type(library, ordinal, idaapi.NTF_REPLACE | idaapi.NTF_SYMU, temporary, *serialized[:1]) if serialized else idaapi.TERR_SAVE
        try:
            yield temporary if res == idaapi.TERR_OK else original

        finally:
            res = idaapi.set_numbered_type(library, ordinal, idaapi.NTF_REPLACE | idaapi.NTF_SYMU, original, *serialized[:1]) if serialized else idaapi.TERR_OK

        # if we couldn't reapply the type then this is critical and we can only log it.
        if res != idaapi.TERR_OK:
            library_class = library.__class__
            library_desc = "<{:s}; <{:s}>>".format('.'.join([library_class.__module__, library_class.__name__]), internal.utils.string.of(library.desc))
            logging.fatal(u"{:s}.typename({:d}, {:s}{:s}) : Unable to restore the original name (\"{:s}\") to ordinal #{:d} from the \"{:s}\" library which is currently named \"{:s}\".".format('.'.join([__name__, cls.__name__]), ordinal, library_desc, '' if name is None else ", name=\"{:s}\"".format(name), internal.utils.string.escape(original, '"'), ordinal, internal.utils.string.of(library.desc), internal.utils.string.escape(temporary, '"')))
        return

    @classmethod
    @contextlib.contextmanager
    def netnode(cls, identifier, name=None):
        '''Return a context manager that renames the netnode specified by `identifier` with a temporary `name` on entry and restores it on exit.'''
        Funique_name = internal.utils.fcompose(hash, functools.partial(operator.and_, sys.maxsize), functools.partial("{:s}_{:x}_{:x}".format, 'netnode_unique', identifier))

        # loop indefinitely until we get a name that is unique to the type library.
        temporary = name or Funique_name(hash("{:b}".format(identifier)))
        while not temporary or internal.netnode.has(temporary):
            temporary = Funique_name(temporary)

        # get the original netnode name, temporarily rename it, and the yield the temporary name.
        original = internal.netnode.name.get(identifier) or u''
        ok = False if original is None else internal.netnode.name.set(identifier, temporary)
        try:
            yield temporary if ok else original

        finally:
            ok = internal.netnode.name.set(identifier, original) if ok else True

        # if we couldn't restore the name then this is critical, so we log it and where the duplicate is.
        if not ok:
            logging.fatal(u"{:s}.netnode({:#x}{:s}) : Unable to restore the original name (\"{:s}\") for the netnode at {:#x} which is currently named \"{:s}\".".format('.'.join([__name__, cls.__name__]), identifier, '' if name is None else ", name=\"{:s}\"".format(name), internal.utils.string.escape(original, '"'), identifier, internal.utils.string.escape(temporary, '"')))
            logging.info(u"{:s}.netnode({:#x}{:s}) : The original name (\"{:s}\") is currently associated with the netnode at {:#x}.".format('.'.join([__name__, cls.__name__]), identifier, '' if name is None else ", name=\"{:s}\"".format(name), internal.utils.string.escape(original, '"'), internal.netnode.get(original)))
        return

    @classmethod
    @contextlib.contextmanager
    def typeinfo(cls, identifier, formatter=None):
        '''Return a context manager that modifies the names for the type information at the given `identifier` using a `formatter` on entry and restores them on exit.'''
        Funique_name = formatter or internal.utils.fcompose(hash, functools.partial(operator.and_, sys.maxsize), functools.partial("{:s}_{:x}_{:x}".format, '_field_unique', identifier))
        callables = [idaapi.get_tinfo2, idaapi.guess_tinfo2] if idaapi.__version__ < 7.0 else [idaapi.get_tinfo, idaapi.guess_tinfo]
        get_tinfo, guess_tinfo = ((functools.partial(lambda F, ti, ea: F(ea, ti), F) if idaapi.__version__ < 7.0 else F) for F in callables)

        # check the address is a function entrypoint in order to determine how to guess
        # its type and apply it.. then we can snag the type and figure how to use it.
        ti, owners = idaapi.tinfo_t(), {ea for ea in function.owners(identifier)} if idaapi.get_func(identifier) else {}
        guessed, res = (False, idaapi.GUESS_FUNC_OK) if get_tinfo(ti, identifier) else (True, guess_tinfo(ti, identifier))
        ok = identifier in owners if guessed else res != idaapi.GUESS_FUNC_FAILED
        definite = True if node.aflags(identifier, idaapi.AFL_USERTI) else False

        # if we grabbed the type then go through and temporarily rename all of its names.
        original = [] if res == idaapi.GUESS_FUNC_FAILED else tinfo.names(ti)
        if ok:
            temporary = tinfo.names(ti, [name for name in map(Funique_name, original if formatter else enumerate(original))]) if original else ti
            ok = idaapi.apply_tinfo(identifier, temporary, idaapi.TINFO_STRICT | (idaapi.TINFO_DEFINITE if definite else idaapi.TINFO_GUESSED))

        # if we snagged the type then use it.. but if we GUESS_FUNC_FAILED, then use None.
        else:
            ok, temporary = False, None if res == idaapi.GUESS_FUNC_FAILED else ti

        # now we can yield the address and the type that we figured out.
        try:
            yield identifier, temporary

        # reapply the previous type to restore it. if we couldn't apply the type
        # previously (and didn't), then there's no need to restore anything.
        finally:
            ok = idaapi.apply_tinfo(identifier, ti, idaapi.TINFO_STRICT | (idaapi.TINFO_DEFINITE if definite else idaapi.TINFO_GUESSED)) if ok else True

        # if we were supposed to restore the type and couldn't, then we need tocomplain.
        if not ok:
            logging.fatal(u"{:s}.typeinfo({:#x}{:s}) : Unable to restore the original type (\"{:s}\") for the item at {:#x} which is currently typed \"{:s}\".".format('.'.join([__name__, cls.__name__]), identifier, '' if formatter is None else ", formatter={:s}".format("{!s}".format(formatter) if callable(formatter) else "{!r}".format(formatter)), internal.utils.string.escape("{!s}".format(ti), '"'), identifier, internal.utils.string.escape("{!s}".format(temporary), '"')))
            logging.info(u"{:s}.typeinfo({:#x}{:s}) : The netnode at {:#x} is still using the temporary names{:s}.".format('.'.join([__name__, cls.__name__]), identifier, '' if formatter is None else ", formatter=\"{:s}\"".format("{!s}".format(formatter) if callable(formatter) else "{!r}".format(formatter)), identifier, " ({:s})".format(', '.join(internal.utils.string.escape(name, '"') for name in tinfo.names(temporary))) if tinfo.names(temporary) else ''))
        return

    # getting and setting a name for a particular address.

    @classmethod
    def get(cls, ea, *flags):
        '''Return the name defined at the address or identifier specified by `ea`.'''
        ea = int(ea)

        # on older versions of the disassembler, we need to check if get_true_name
        # is going to return the function's name instead of a local one.
        if idaapi.__version__ < 6.8:
            fn = idaapi.get_func(ea)
            res = None if fn and range.start(fn) == ea and not flags else idaapi.get_true_name(ea) or idaapi.get_true_name(ea, ea)
            return internal.utils.string.of(aname) or None

        # if we were given a node identifier, then we return the netnode name.
        elif node.identifier(ea):
            return internal.netnode.name.get(ea)

        # otherwise we can use `idaapi.get_ea_name` with the flags for the address name.
        aname = idaapi.get_ea_name(ea, *flags) if flags else idaapi.get_ea_name(ea, idaapi.GN_LOCAL)
        return internal.utils.string.of(aname) or None

    @classmethod
    def set(cls, ea, string, *flags_requested):
        '''Update the name for the address or identifier in `ea` to `string` using the given `flags` within the `requested` bits.'''
        ea, ff, Fget_name, Fapply_name, default = int(ea), address.flags(int(ea)), cls.get, idaapi.set_name, {}

        # unpack any parameters that were given to us and include reasonable
        # defaults that preserve the different name flags that we support.
        keep = [idaapi.SN_PUBLIC|idaapi.SN_NON_PUBLIC, idaapi.SN_WEAK|idaapi.SN_NON_WEAK, idaapi.SN_AUTO|idaapi.SN_NON_AUTO, idaapi.SN_LOCAL]
        [flags, requested] = itertools.chain(flags_requested, [0, None][len(flags_requested) - 2:] if len(flags_requested) < 2 else [])
        requested = functools.reduce(operator.or_, [item for item in keep if flags & item], 0) if requested is None else requested

        # we first need to figure out what default flags to use based on the address.
        # so we start by disabling checks and ensuring it's not autogenerated.
        default[idaapi.SN_NON_AUTO] = idaapi.SN_NON_AUTO
        default[idaapi.SN_NOCHECK] = idaapi.SN_NOCHECK

        # if our name is listed, a public, or a weak name, then preserve those flags
        # before applying anything. we do this since we have to specially handle SN_NOLIST.
        public, weak, listed = idaapi.is_public_name(ea), idaapi.is_weak_name(ea), idaapi.is_in_nlist(ea)
        default[idaapi.SN_NOLIST] = 0 if listed else idaapi.SN_NOLIST

        SN_AUTO, SN_WEAK, SN_PUBLIC = idaapi.SN_AUTO|idaapi.SN_NON_AUTO, idaapi.SN_WEAK|idaapi.SN_NON_WEAK, idaapi.SN_PUBLIC|idaapi.SN_NON_PUBLIC
        default.setdefault(SN_WEAK, idaapi.SN_WEAK) if weak else default.setdefault(SN_WEAK, idaapi.SN_NON_WEAK)
        default.setdefault(SN_PUBLIC, idaapi.SN_PUBLIC) if public else default.setdefault(SN_PUBLIC, idaapi.SN_NON_PUBLIC)

        # start out by checking if we're supposed to rename a netnode.
        if node.identifier(ea):
            Fget_name, Fapply_name = internal.netnode.name.get, internal.netnode.name.set
            used, wanted, parameters = 0, 0, []

        # if we're not within a function, then we're naming outside any kind of scope
        # and so our default flags only disable the ones that don't make any sense.
        elif not function.has(ea):
            default[idaapi.SN_LOCAL] = default[idaapi.SN_NON_AUTO] = 0
            used, wanted = functools.reduce(operator.or_, default, 0), functools.reduce(operator.or_, (item for _, item in default.items()), 0)
            parameters = [(used & wanted & ~requested) | flags]

        # otherwise, we're within a function and we have a whole lot of work to do.
        else:
            default.update(cls.__name_within(ea, flags, requested))
            used, wanted = functools.reduce(operator.or_, default, 0), functools.reduce(operator.or_, (item for _, item in default.items()), 0)
            parameters = [(used & wanted & ~requested) | flags]

        # Apply the name in `string` to the address `ea` with the specified `flags`.
        ida_string = internal.utils.string.to(string or u'')

        # validate the name that we're going to apply.
        res = idaapi.validate_name2(ida_string[:]) if idaapi.__version__ < 7.0 else idaapi.validate_name(ida_string[:], idaapi.SN_IDBENC)
        if ida_string and ida_string != res:
            logging.info(u"{:s}.name({:#x}, \"{:s}\", {:#x}) : Stripping invalid chars from specified name resulted in \"{:s}\".".format('database', ea, internal.utils.string.escape(string, '"'), flags, internal.utils.string.escape(internal.utils.string.of(res), '"')))
            ida_string = res

        # fetch the old name and set the new one at the same time.
        res, ok = Fget_name(ea), Fapply_name(ea, ida_string, *parameters)
        if not ok:
            raise internal.exceptions.DisassemblerError(u"{:s}.name({:#x}, \"{:s}\", {:#x}) : Unable to call `{:s}({:#x}, \"{:s}\", {:#0{:d}x} & {:#0{:d}x} | {:#0{:d}x})`.".format('database', ea, internal.utils.string.escape(string, '"'), flags, internal.utils.pycompat.fullname(Fapply_name), ea, internal.utils.string.escape(string, '"'), idaapi.BADADDR & used & wanted, 2 + 8, idaapi.BADADDR & ~requested, 2 + 8, idaapi.BADADDR & flags, 2 + 8))
        return res

    # define a private method for handling the name variation inside a function.

    @classmethod
    def __name_within(cls, ea, flags, requested):
        '''Return the default for setting the name or label at address `ea` within a function using the suggested `flags` with the `requested` bits.'''
        result, func, realname, localname = {}, idaapi.get_func(ea), idaapi.get_visible_name(ea), idaapi.get_visible_name(ea, idaapi.GN_LOCAL)

        # if we're pointing at the start of the function, then we need to set a
        # local name unless one of the supported flags was explicitly specified.
        if func and range.start(func) == ea and not requested & idaapi.SN_LOCAL and not any(flags & requested & item for item in [idaapi.SN_PUBLIC, idaapi.SN_NON_PUBLIC, idaapi.SN_WEAK, idaapi.SN_NON_WEAK, idaapi.SN_AUTO, idaapi.SN_NON_AUTO]):
            result[idaapi.SN_LOCAL] = idaapi.SN_LOCAL

        # if there's a public name at this address then use the suggestion to
        # determine whether we keep it public or not.
        elif idaapi.is_public_name(ea) or any(flags & requested & item for item in [idaapi.SN_PUBLIC, idaapi.SN_NON_PUBLIC]):
            SN_PUBLIC = idaapi.SN_PUBLIC|idaapi.SN_NON_PUBLIC
            result.setdefault(SN_PUBLIC, idaapi.SN_PUBLIC) if flags & requested & idaapi.SN_PUBLIC else result.setdefault(SN_PUBLIC, idaapi.SN_NON_PUBLIC)

        # if there's a weak name at this address then use the suggestion to
        # determine whether it shall remain weak or not.
        elif idaapi.is_weak_name(ea) or any(flags & requested & item for item in [idaapi.SN_WEAK, idaapi.SN_NON_WEAK]):
            SN_WEAK = idaapi.SN_WEAK|idaapi.SN_NON_WEAK
            result.setdefault(SN_WEAK, idaapi.SN_WEAK) if flags & requested & idaapi.SN_WEAK else result.setdefault(SN_WEAK, idaapi.SN_NON_WEAK)

        # if the caller explicitly wanted it listed, then we need to check if there's
        # a local name. this is so we can remove it in order to avoid a collision.
        elif requested & idaapi.SN_NOLIST and flags & requested & idaapi.SN_NOLIST == 0:
            if localname and realname != localname:
                idaapi.del_local_name(ea), idaapi.set_name(ea, localname, idaapi.SN_NOLIST)
            result[idaapi.SN_LOCAL] = 0

        # if a regular name is already defined and it matches the local one, then we
        # avoid making it listed and preserve the original since the caller wasn't explicit.
        elif realname and realname == localname:
            result[idaapi.SN_NOLIST] = idaapi.SN_NOLIST

        # otherwise, we're using a local name because we're inside a function.
        else:
            result[idaapi.SN_LOCAL] = idaapi.SN_LOCAL
        return result

class entries(object):
    """
    This tiny namespace is a wrapper around the entry point component
    of the disassembler. Entry points are also known as the export
    table in Windows parlance. The disassembler differentiates an
    entry point from an export using its ordinal number and address.
    Hence, this namespace does the same and allows one to read or
    write to any of the entry points or exports within the database.

    The native type that is used by this namespace is the index of
    the entry point. One can use the index of an entry point to
    determine its ordinal, name, or addresses. It is worth noting
    that a single entry point can have multiple ordinals or names.
    """

    # This netnode uses alts and sups where the alts have a format where each
    # ordinal is set to address+1 (NETMAP_VAL), and the BADADDR index is the
    # number of entries. The sups map ordinal to a terminated string for the name.
    __netnode_name__ = '$ entry points'

    @classmethod
    def count(cls):
        '''Return the total number of entry points within the database.'''
        return idaapi.get_entry_qty()

    @classmethod
    def new(cls, ea, name=None, *ordinal, **code):
        """Create a new entry point at the address `ea` with the specified `name` and `ordinal`.

        If `code` is false then avoid creating instructions at the specified address.
        """
        [realordinal] = ordinal if ordinal else [ea]

        # We assume by default that adding an entry point is for marking it
        # as code. There could be data imports, but why would anybody be
        # using their disassembler to manually create their imports anyways...
        mark_as_code = code.get('code', True)

        # Now we can go ahead and tell the disassembler to add an entry.
        index = idaapi.get_entry_qty()
        if not idaapi.add_entry(realordinal, ea, internal.utils.string.to(name) if name else None, mark_as_code):
            raise internal.exceptions.DisassemblerError(u"{:s}.new({:#x}, {!s}{:s}{:s}) : Unable to create an entry point at the specified address ({:#x}).".format('.'.join([__name__, cls.__name__]), ea, u"{!s}".format(name) if isinstance(name, internal.types.string) else name, u", {:d}".format(realordinal) if ordinal else u'', u", {:s}".format(internal.utils.string.kwargs(code)) if code else u'', ea))
        return index

    @classmethod
    def iterate(cls):
        '''Yield a tuple for each entry point and export within the database.'''
        for index in builtins.range(idaapi.get_entry_qty()):
            ordinal = idaapi.get_entry_ordinal(index)
            address, res = (Fget_entry_thing(ordinal) for Fget_entry_thing in [idaapi.get_entry, idaapi.get_entry_name])
            name = internal.utils.string.of(res) if res else None
            yield index, address, name, ordinal
        return

    @classmethod
    def exports(cls):
        '''Yield a tuple for each export within the database.'''
        for index, address, name, ordinal in cls.iterate():
            if ordinal != address:
                yield (index, address, name, ordinal)
            continue
        return

    @classmethod
    def entries(cls):
        '''Yield a tuple for each entry point within the database.'''
        for index, address, name, ordinal in cls.iterate():
            if ordinal == address:
                yield (index, address, name)
            continue
        return

    @classmethod
    def name(cls, index, *name):
        '''Return or set the `name` of the entry point at the specified `index`.'''
        ordinal = idaapi.get_entry_ordinal(index)
        res = idaapi.get_entry_name(ordinal)
        if not name:
            return internal.utils.string.of(res) if res else ''

        # Otherwise, go ahead and rename the entry using the disassembler.
        [newname] = name
        if not idaapi.rename_entry(ordinal, internal.utils.string.to(newname)):
            raise internal.exceptions.DisassemblerError(u"{:s}.name({:d}, {!r}) : Unable to set the name for the entry point at the specified index ({:d}).".format('.'.join([__name__, cls.__name__]), index, newname, index))
        return internal.utils.string.of(res)

    @classmethod
    def fullname(cls, index):
        '''Return the full symbol name of the entry point at the specified `index`.'''
        module, res = database.filename(), cls.name(index)
        if database.filetype() in {idaapi.f_ELF, idaapi.f_AOUT}:
            return name.format_long("'{:s}'".format(module), res or None, idaapi.get_entry_ordinal(index))
        return name.format_long(module, res or None, idaapi.get_entry_ordinal(index))

    @classmethod
    def ordinal(cls, index):
        '''Return the ordinal of the entry point at the specified `index`.'''
        return idaapi.get_entry_ordinal(index)

    @classmethod
    def address(cls, index):
        '''Return the address of the entry point at the specified `index`.'''
        ordinal = idaapi.get_entry_ordinal(index)
        ea = idaapi.get_entry(ordinal)
        return None if ea == idaapi.BADADDR else ea

    @classmethod
    def forward(cls, index, *name):
        '''Return or set the forwarded `name` of the entry point at the specified `index`.'''
        ordinal = idaapi.get_entry_ordinal(index)
        res = idaapi.get_entry_forwarder(ordinal)
        if not name:
            return internal.utils.string.of(res or '') if ordinal > 0 else None

        # If the API doesn't exist, then bail with a version complaint.
        elif not hasattr(idaapi, 'set_entry_forwarder'):
            raise internal.exceptions.UnsupportedVersion(u"{:s}.forwarder({:d}, {!r}) : Setting the forwarded name for an entry point is not supported by your version of the disassembler ({!s}).".format('.'.join([__name__, cls.__name__]), index, u"{!s}".format(*name), idaapi.__version__))

        # Now we can just hand off the name to the disassembler.
        [newname] = name
        if not idaapi.set_entry_forwarder(ordinal, internal.utils.string.to(newname)):
            raise internal.exceptions.DisassemblerError(u"{:s}.forwarder({:d}, {!r}) : Unable to set the forwarded name for entry point at the specified index ({:d}).".format('.'.join([__name__, cls.__name__]), index, newname, index))
        return internal.utils.string.of(res)

    @classmethod
    def has(cls, index):
        '''Return whether the entry point with the specified `index` is within the database.'''
        return 0 <= idaapi.get_entry_qty() < index and idaapi.get_entry_ordinal(index) > 0

    @classmethod
    def has_ordinal(cls, ordinal):
        '''Return whether the entry point with the specified `ordinal` is within the database.'''
        return idaapi.get_entry(ordinal) != idaapi.BADADDR

    @classmethod
    def has_address(cls, ea):
        '''Return whether the address specified by `ea` is an entry point.'''
        is_entrypoint = idaapi.get_entry(ea) == ea
        iterable = (True for index in builtins.range(idaapi.get_entry_qty()) if idaapi.get_entry(idaapi.get_entry_ordinal(index)) == ea)
        return is_entrypoint or next(iterable, False)

    @classmethod
    def at_address(cls, ea):
        '''Yield the index of each entry point at the address specified by `ea`.'''
        # There just isn't a faster way than O(n) to accomplish this
        # without having to keep track of the address ourselves...
        for index in builtins.range(idaapi.get_entry_qty()):
            ordinal = idaapi.get_entry_ordinal(index)
            if ordinal > 0 and idaapi.get_entry(ordinal) == ea:
                yield index
            continue
        return

    @classmethod
    def at_name(cls, name):
        '''Yield the index of each entry point with the specified `name`.'''
        # Entry point names are not guaranteed to be unique, and we have
        # no other way to find the indices for a name other than O(n).
        for index in builtins.range(idaapi.get_entry_qty()):
            ordinal = idaapi.get_entry_ordinal(index)
            res = internal.utils.string.of(idaapi.get_entry_name(ordinal) or '') if ordinal > 0 else u''
            if ordinal > 0 and name == res:
                yield index
            continue
        return

    @classmethod
    def by_ordinal(cls, ordinal):
        '''Return the index of the entry point for the specified `ordinal`.'''
        if idaapi.get_entry(ordinal) == idaapi.BADADDR:
            raise internal.exceptions.ItemNotFoundError(u"{:s}.by_ordinal({:d}) : No entry point was found with the specified ordinal ({:d}).".format('.'.join([__name__, cls.__name__]), ordinal, ordinal))

        # It appears that we have no choice other than to iterate through all
        # of the ordinals to find the index that matches the desired ordinal.
        # We really should be keeping track of this index by ourselves...
        for index in builtins.range(idaapi.get_entry_qty()):
            if ordinal == idaapi.get_entry_ordinal(index):
                return index
            continue
        raise internal.exceptions.ItemNotFoundError(u"{:s}.by_ordinal({:d}) : No entry point was found with the specified ordinal ({:d}).".format('.'.join([__name__, cls.__name__]), ordinal, ordinal))

class exceptions(object):
    """
    This namespace is used to extract exception information from the
    disassembler.
    """
    __error_codes__ = [(attribute, getattr(idaapi, attribute)) for attribute in dir(idaapi) if attribute.startswith('TBERR_')]
    __error_names__ = {value : attribute for attribute, value in __error_codes__}

    # FIXME: the tryblks.hpp api doesn't actually expose anything that we can
    #        use for identifying the handler associated with a RUNTIME_FUNCTION.

    @classmethod
    def format(cls, error):
        if error in cls.__error_names__:
            return "{:s}({:#x})".format(cls.__error_names__[error], error)
        return "{:#x}".format(error)

    @classmethod
    def iterate(cls, start, stop):
        TBERR_OK, TB_SEH, TB_CPP = (getattr(idaapi, attribute, index) for index, attribute in enumerate(['TBERR_OK', 'TB_SEH', 'TB_CPP']))
        blks, area = idaapi.tryblks_t(), range.pack(start, stop)
        count = idaapi.get_tryblks(blks, area)
        if not count:
            raise internal.exceptions.DisassemblerError(u"{:s}.iterate({:#x}, {:#x}) : {:s}".format('.'.join([__name__, cls.__name__]), start, stop, "{!s}".format(count)))
        print('found {:d} tryblks'.format(count))

        result, iterable = [], ((index, blks[index]) for index in builtins.range(blks.size()))
        for index, tryblk in iterable:
            level, kind = tryblk.level, tryblk.get_kind()
            handler = cls.handler(tryblk)
            result.append(handler)
        return result

    @classmethod
    def handler(cls, tryblk):
        TBERR_OK, TB_SEH, TB_CPP = (getattr(idaapi, attribute, index) for index, attribute in enumerate(['TBERR_OK', 'TB_SEH', 'TB_CPP']))

        level, kind = tryblk.level, tryblk.get_kind()
        if kind not in {TB_SEH, TB_CPP}:
            raise internal.exceptions.InvalidTypeOrValueError(u"{:s}.handler(...) : level={:#x} invalid kind {:#x}.".format('.'.join([__name__, cls.__name__]), level, kind))

        iterable = [(index, tryblk[index]) for index in builtins.range(tryblk.size())]
        ranges = [range.bounds(area) for index, area in iterable]

        if kind == TB_SEH:
            handler = tryblk.seh()
            disp, fpreg = handler.disp, handler.fpreg

            iterable = (handler[index] for index in builtins.range(handler.size()))
            catches = [range.bounds(area) for area in iterable]

            iterable = (handler.filter[index] for index in builtins.range(handler.filter.size()))
            filters = [range.bounds(area) for area in iterable]

            packed = handler.seh_code, filters
            return level, ranges, (disp, fpreg, catches, packed)

        handlers = tryblk.cpp()
        iterable = (handlers[index] for index in builtins.range(handlers.size()))
        packed = [(catch.obj, catch.type_id) for catch in iterable]
        return level, ranges, packed

    @classmethod
    def blocks(cls, tryblk):
        iterable = (tryblk[index] for index in builtins.range(tryblk.size()))
        return [range.unpack(blk) for blk in iterable]
