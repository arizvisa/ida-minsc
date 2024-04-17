r"""
Hexrays module (internal)

This module wraps a number of features provided by the Hex-Rays decompiler
so that it can be dumbed down a bit. This module is used internally and thus
doesn't provide anything that a user should find useful. Nonetheless, we
document this to allow curious individuals to determine how it all works.
"""

import functools, operator, itertools, logging
import idaapi, database, internal
from internal import utils, interface, types, exceptions

### some decorators to help guard the available of certain functions.
def guarded(callable):
    '''This decorator is just responsible for guarding a function so that it only works when the Hex-Rays Decompiler is initialized.'''
    def wrapper(F, *args, **kwargs):
        if not ida_hexrays.init_hexrays_plugin():
            fullname = '.'.join([getattr(F, attribute) for attribute in ['__module__', '__name__'] if hasattr(F, attribute)])
            raise internal.exceptions.UnsupportedCapability(u"{:s} : Hex-rays is either unable to be initialized or unsupported for the current database.".format(fullname))
        return F(*args, **kwargs)
    def result(F):
        return utils.wrap(F, wrapper)
    return result(callable)

### general utilities to interact with the global state of the decompiler.
@guarded
def version():
    '''Return the version of the decompiler as a 4-element tuple that can be compared.'''
    Fmake_number = utils.fcatch(unparseable=None)(unparseable=0.0)(float)
    Fattempt_integer = utils.fcondition(lambda number: int(number) == number)(int, float)

    version = ida_hexrays.get_hexrays_version() or '0.0.0.0'
    components = version.split('.', 3)
    numerical = map(Fmake_number, components)
    integers_and_floats = map(Fattempt_integer, numerical)
    return tuple(integers_and_floats)

### this closure returns a descriptor which will give priority to one object when fetching a
### specific attribute, and fall back to the other object when if the attribute was not found.
def missing_descriptor(module, missing):
    """Return a descriptor that attempts to fetch an attribute from the given `module`, or returns the one from `missing`."

    If a callable ends up being fetched from `missing`, the callable is executed with the desired module and attribute.
    """
    class descriptor(object):
        def __init__(self, attribute):
            missing_attribute = getattr(missing, attribute, None)
            if hasattr(module, attribute):
                self.__result__ = getattr(module, attribute)
            elif hasattr(missing, attribute) and callable(getattr(missing, attribute)):
                Fmissing_attribute = utils.pycompat.function.extract(missing_attribute)
                self.__result__ = Fmissing_attribute(module, attribute)
            else:
                self.__result__ = getattr(missing, attribute)
            return
        def __get__(self, obj, type=None):
            return self.__result__
    return descriptor

def new_partial_api(name, object, descriptor):
    '''Create a new type with the specified `name` that contains the specified `descriptor` for each attribute inside `object`.'''
    namespace = { attribute : descriptor(attribute) for attribute, _ in object.__dict__.items() if not attribute.startswith('_') }
    return type(name, (object,), namespace)

def missing_callable(object, attribute):
    '''Return a callable for ``missing_descriptor`` that will raise an ``UnsupportedCapability`` exception when called.'''
    def missing_callable(*args, **kwargs):
        '''This api is inaccessible either due to an error during import or is missing from the "ida_hexrays" module.'''
        raise internal.exceptions.UnsupportedCapability(u"The requested function \"{:s}\" is currently inaccessible or is missing.".format(utils.string.escape('.'.join([object.__name__, attribute]), '"')))
    return missing_callable

def simulate_missing_callable(level, Fcallable):
    '''Return a callable for ``missing_descriptor`` that will log an ``UnsupportedCapability`` exception and then call the given `callable` to return its result.'''
    def simulate_missing_callable(object, attribute):
        '''This api is inaccessible either due to an error during import or is missing from the "ida_hexrays" module.'''
        def simulate_missing_callable(Fcallable, Fraise_exception, *args, **kwargs):
            try:
                discard = Fraise_exception(*args, **kwargs)
                raise AssertionError(u"An unexpected error has occurred when trying to raise an exception for the missing attribute \"{:s}\".".format(utils.string.escape('.'.join([object.__name__, attribute]), '"')))
            except internal.exceptions.UnsupportedCapability as E:
                logging.log(level, u"Simulating the requested function \"{:s}\" due to it being currently inaccessible or missing.".format(utils.string.escape('.'.join([object.__name__, attribute]), '"')))
            return Fcallable(*args, **kwargs)
        return functools.partial(simulate_missing_callable, Fcallable, missing_callable(object, attribute))
    return simulate_missing_callable

def missing_callable(object, attribute):
    '''Return a callable for ``missing_descriptor`` that will raise an ``UnsupportedCapability`` exception when called.'''
    def missing_callable(*args, **kwargs):
        '''This api is inaccessible either due to an error during import or is missing from the "ida_hexrays" module.'''
        raise internal.exceptions.UnsupportedCapability(u"The requested function \"{:s}\" is currently inaccessible or is missing.".format(utils.string.escape('.'.join([object.__name__, attribute]), '"')))
    return missing_callable

def use_callable(callable):
    '''Return a callable that when used by ``missing_descriptor``, will return the specified `callable`.'''
    def use_callable(object, attribute):
        return callable
    return use_callable

def missing_class(module, attribute):
    '''Return a class for ``missing_descriptor`` that will raise an ``UnsupportedCapability`` exception when used.'''
    class missing_class(object):
        def __new__(*args, **kwargs):
            '''This api is inaccessible either due to an error during import or is missing from the "ida_hexrays" module.'''
            raise internal.exceptions.UnsupportedCapability(u"The requested class \"{:s}\" is currently inaccessible or is missing.".format(utils.string.escape('.'.join([module.__name__, attribute]), '"')))
        __slots__ = ()
    return missing_class

def use_class(type):
    '''Return a callable that when used by ``missing_descriptor``, will return the specified `type`.'''
    def use_class(object, attribute):
        return type
    return use_class

### This class is to provide a backing namespace for things missing from the "ida_hexrays" module.
class ida_hexrays_template(object):
    """
    This class is just a template for the "ida_hexrays" module and
    is used to generate a namespace that can be substitued in place
    of the module in case there's any attrbutes that might be missing.
    """

    mop_z = 0x0
    mop_r, mop_n, mop_str = 0x1, 0x2, 0x3
    mop_d, mop_S, mop_v   = 0x4, 0x5, 0x6
    mop_b, mop_f, mop_l   = 0x7, 0x8, 0x9
    mop_a, mop_h, mop_c   = 0xa, 0xb, 0xc
    mop_fn, mop_p, mop_sc = 0xd, 0xe, 0xf

    m_nop = 0x00
    m_stx = 0x01
    m_ldx = 0x02
    m_ldc = 0x03
    m_mov = 0x04
    m_neg = 0x05
    m_lnot = 0x06
    m_bnot = 0x07
    m_xds = 0x08
    m_xdu = 0x09
    m_low = 0x0a
    m_high = 0x0b
    m_add = 0x0c
    m_sub = 0x0d
    m_mul = 0x0e
    m_udiv = 0x0f
    m_sdiv = 0x10
    m_umod = 0x11
    m_smod = 0x12
    m_or = 0x13
    m_and = 0x14
    m_xor = 0x15
    m_shl = 0x16
    m_shr = 0x17
    m_sar = 0x18
    m_cfadd = 0x19
    m_ofadd = 0x1a
    m_cfshl = 0x1b
    m_cfshr = 0x1c
    m_sets = 0x1d
    m_seto = 0x1e
    m_setp = 0x1f
    m_setnz = 0x20
    m_setz = 0x21
    m_setae = 0x22
    m_setb = 0x23
    m_seta = 0x24
    m_setbe = 0x25
    m_setg = 0x26
    m_setge = 0x27
    m_setl = 0x28
    m_setle = 0x29
    m_jcnd = 0x2a
    m_jnz = 0x2b
    m_jz = 0x2c
    m_jae = 0x2d
    m_jb = 0x2e
    m_ja = 0x2f
    m_jbe = 0x30
    m_jg = 0x31
    m_jge = 0x32
    m_jl = 0x33
    m_jle = 0x34
    m_jtbl = 0x35
    m_ijmp = 0x36
    m_goto = 0x37
    m_call = 0x38
    m_icall = 0x39
    m_ret = 0x3a
    m_push = 0x3b
    m_pop = 0x3c
    m_und = 0x3d
    m_ext = 0x3e
    m_f2i = 0x3f
    m_f2u = 0x40
    m_i2f = 0x41
    m_u2f = 0x42
    m_f2f = 0x43
    m_fneg = 0x44
    m_fadd = 0x45
    m_fsub = 0x46
    m_fmul = 0x47
    m_fdiv = 0x48

    MMIDX_GLBLOW = 0
    MMIDX_LVARS = 1
    MMIDX_RETADDR = 2
    MMIDX_SHADOW = 3
    MMIDX_ARGS = 4
    MMIDX_GLBHIGH = 5

    DECOMP_NO_WAIT = 1
    DECOMP_NO_CACHE = 2
    DECOMP_NO_FRAME = 4
    DECOMP_WARNINGS = 8
    DECOMP_ALL_BLKS = 0x10
    DECOMP_NO_HIDE = 0x20
    DECOMP_NO_XREFS = 0x40
    DECOMP_VOID_MBA = 0x100

    MMAT_ZERO = 0
    MMAT_GENERATED = 1
    MMAT_PREOPTIMIZED = 2
    MMAT_LOCOPT = 3
    MMAT_CALLS = 4
    MMAT_GLBOPT1 = 5
    MMAT_GLBOPT2 = 6
    MMAT_GLBOPT3 = 7
    MMAT_LVARS = 8

    MERR_OK = 0
    MERR_BLOCK = 1
    MERR_INTERR = -1
    MERR_INSN = -2
    MERR_MEM = -3
    MERR_BADBLK = -4
    MERR_BADSP = -5
    MERR_PROLOG = -6
    MERR_SWITCH = -7
    MERR_EXCEPTION = -8
    MERR_HUGESTACK = -9
    MERR_LVARS = -10
    MERR_BITNESS = -11
    MERR_BADCALL = -12
    MERR_BADFRAME = -13
    MERR_UNKTYPE = -14
    MERR_BADIDB = -15
    MERR_SIZEOF = -16
    MERR_REDO = -17
    MERR_CANCELED = -18
    MERR_RECDEPTH = -19
    MERR_OVERLAP = -20
    MERR_PARTINIT = -21
    MERR_COMPLEX = -22
    MERR_LICENSE = -23
    MERR_ONLY32 = -24
    MERR_ONLY64 = -25
    MERR_BUSY = -26
    MERR_FARPTR = -27
    MERR_EXTERN = -28
    MERR_FUNCSIZE = -29
    MERR_BADRANGES = -30

    USE_KEYBOARD = 0
    USE_MOUSE = 1
    USE_CURLY_BRACES = 2

    MLI_NAME = 1
    MLI_TYPE = 2
    MLI_CMT = 4
    MLI_SET_FLAGS = 8
    MLI_CLR_FLAGS = 16

    SVW_INT = 0
    SVW_FLOAT = 1
    SVW_SOFT = 2

    MBL_NONFAKE = 0
    MBL_PRIV = 1
    MBL_FAKE = 2
    MBL_GOTO = 4
    MBL_TCAL = 8
    MBL_PUSH = 16
    MBL_DMT64 = 32
    MBL_COMB = 64
    MBL_PROP = 128
    MBL_DEAD = 256
    MBL_LIST = 512
    MBL_INCONST = 1024
    MBL_CALL = 2048
    MBL_BACKPROP = 4096
    MBL_NORET = 8192
    MBL_DSLOT = 16384
    MBL_VALRANGES = 32768
    MBL_KEEP = 65536

    BLT_NONE = 0
    BLT_STOP = 1
    BLT_0WAY = 2
    BLT_1WAY = 3
    BLT_2WAY = 4
    BLT_NWAY = 5
    BLT_XTRN = 6

    MUST_ACCESS = 0
    MAY_ACCESS = 1
    MAYMUST_ACCESS_MASK = 1

    INCLUDE_SPOILED_REGS = 64
    INCLUDE_UNUSED_SRC = 2048
    INCLUDE_DEAD_RETREGS = 4096
    INCLUDE_RESTRICTED = 8192

    GC_REGS_AND_STKVARS = 0
    GC_ASR = 1
    GC_XDSU = 2
    GC_END = 3
    GC_DIRTY_ALL = 63

    ROLE_UNK = 0x00
    ROLE_EMPTY = 0x01
    ROLE_MEMSET = 0x02
    ROLE_MEMSET32 = 0x03
    ROLE_MEMSET64 = 0x04
    ROLE_MEMCPY = 0x05
    ROLE_STRCPY = 0x06
    ROLE_STRLEN = 0x07
    ROLE_STRCAT = 0x08
    ROLE_TAIL = 0x09
    ROLE_BUG = 0x0a
    ROLE_ALLOCA = 0x0b
    ROLE_BSWAP = 0x0c
    ROLE_PRESENT = 0x0d
    ROLE_CONTAINING_RECORD = 0x0e
    ROLE_FASTFAIL = 0x0f
    ROLE_READFLAGS = 0x10
    ROLE_IS_MUL_OK = 0x11
    ROLE_SATURATED_MUL = 0x12
    ROLE_BITTEST = 0x13
    ROLE_BITTESTANDSET = 0x14
    ROLE_BITTESTANDRESET = 0x15
    ROLE_BITTESTANDCOMPLEMENT = 0x16
    ROLE_VA_ARG = 0x17
    ROLE_VA_COPY = 0x18
    ROLE_VA_START = 0x19
    ROLE_VA_END = 0x1a
    ROLE_ROL = 0x1b
    ROLE_ROR = 0x1c
    ROLE_CFSUB3 = 0x1d
    ROLE_OFSUB3 = 0x1e
    ROLE_ABS = 0x1f
    ROLE_3WAYCMP0 = 0x20
    ROLE_3WAYCMP1 = 0x21
    ROLE_WMEMCPY = 0x22
    ROLE_WMEMSET = 0x23
    ROLE_WCSCPY = 0x24
    ROLE_WCSLEN = 0x25
    ROLE_WCSCAT = 0x26
    ROLE_SSE_CMP4 = 0x27
    ROLE_SSE_CMP8 = 0x28

    FCI_PROP = 0x1
    FCI_DEAD = 0x2
    FCI_FINAL = 0x4
    FCI_NORET = 0x8
    FCI_PURE = 0x10
    FCI_NOSIDE = 0x20
    FCI_SPLOK = 0x40
    FCI_HASCALL = 0x80
    FCI_HASFMT = 0x100
    FCI_EXPLOCS = 0x400

    hexrays_failure_t = missing_class
    mba_ranges_t = missing_class
    mlist_t = missing_class
    gco_info_t = missing_class
    mba_t = missing_class
    mop_t = missing_class
    minsn_t = missing_class
    lvar_t = missing_class
    stkvar_ref_t = missing_class
    rlist_t = missing_class
    ivlset_t = missing_class
    lvars_t = missing_class
    lvar_locator_t = missing_class
    var_ref_t = missing_class
    lvar_ref_t = missing_class
    cfunc_t = missing_class
    cfuncptr_t = missing_class
    vdloc_t = missing_class
    lvar_saved_info_t = missing_class
    mblock_t = missing_class
    op_parent_info_t = missing_class
    voff_t = missing_class
    vivl_t = missing_class

    init_hexrays_plugin = use_callable(utils.fconstant(False))
    get_hexrays_version = use_callable(utils.fconstant('0.0.0.0'))
    decompile = use_callable(utils.fconstant(None))

    def __decompile_func(pfn, hf, decomp_flags):
        ea = interface.range.start(pfn)
        return idaapi.decompile(pfn, hf)
    decompile_func = use_callable(__decompile_func)

    gen_microcode = simulate_missing_callable(logging.WARNING, utils.fconstant(None))
    get_widget_vdui = missing_callable
    get_current_operand = missing_callable
    modify_user_lvar_info = missing_callable

    def __get_merror_desc(code, mba):
        error_description = {
            0: 'ok',
            1: 'no error, switch to new block',
            -1: 'internal error',
            -2: 'cannot convert to microcode',
            -3: 'not enough memory',
            -4: 'bad block found',
            -5: 'positive sp value has been found',
            -6: 'prolog analysis failed',
            -7: 'wrong switch idiom',
            -8: 'exception analysis failed',
            -9: 'stack frame is too big',
            -10: 'local variable allocation failed',
            -11: '16-bit functions cannot be decompiled',
            -12: 'could not determine call arguments',
            -13: 'function frame is wrong',
            -14: 'undefined type %s (currently unused error code)',
            -15: 'inconsistent database information',
            -16: 'wrong basic type sizes in compiler settings',
            -17: 'redecompilation has been requested',
            -18: 'decompilation has been cancelled',
            -19: 'max recursion depth reached during lvar allocation',
            -20: 'variables would overlap: %s',
            -21: 'partially initialized variable %s',
            -22: 'too complex function',
            -23: 'no license available',
            -24: 'only 32-bit functions can be decompiled for the current database',
            -25: 'only 64-bit functions can be decompiled for the current database',
            -26: 'already decompiling a function',
            -27: 'far memory model is supported only for pc',
            -28: 'special segments cannot be decompiled',
            -29: 'too big function',
            -30: 'bad input ranges',
        }
        return error_description.get(code, "error {:d}".format(code))

    get_merror_desc = use_callable(__get_merror_desc)

    get_mreg_name = missing_callable
    reg2mreg = missing_callable
    mreg2reg = missing_callable
    is_kreg = missing_callable

    VDI_NONE = 0
    VDI_EXPR = 1
    VDI_LVAR = 2
    VDI_FUNC = 3
    VDI_TAIL = 4

    RETRIEVE_ONCE = 0
    RETRIEVE_ALWAYS = 1

    ITP_EMPTY = 0
    ITP_ARG1 = 1
    ITP_ARG64 = 64
    ITP_BRACE1 = 65
    ITP_INNER_LAST = 65
    ITP_ASM = 66
    ITP_ELSE = 67
    ITP_DO = 68
    ITP_SEMI = 69
    ITP_CURLY1 = 70
    ITP_CURLY2 = 71
    ITP_BRACE2 = 72
    ITP_COLON = 73
    ITP_BLOCK1 = 74
    ITP_BLOCK2 = 75
    ITP_SIGN = 536870912
    ITP_CASE = 1073741824

    citem_t = missing_class
    cnumber_t = missing_class
    cinsn_t = missing_class
    cexpr_t = missing_class
    ctree_item_t = missing_class
    treeloc_t = missing_class

# Try and import the module. If we can, then all the attributes from our descriptor
# should end up being forwarded directly to the module as they originally were.
try:
    hexrays_descriptor = missing_descriptor(__import__('ida_hexrays'), ida_hexrays_template)

# If we couldn't import the "ida_hexrays" module, then this descriptor acts as a
# compatibility layer that allows users of the module to still be compiled (evaluated).
except ImportError:
    hexrays_descriptor = missing_descriptor(object, ida_hexrays_template)

# Use the template to generate a new object that wraps the "ida_hexrays" module.
ida_hexrays = new_partial_api('ida_hexrays', ida_hexrays_template, hexrays_descriptor)

# ...and then delete all the things that we don't need anymore.
del(ida_hexrays_template)
del(hexrays_descriptor)
del(new_partial_api)

### The following class is intended to be used by pattern-matching
### so that importing a plugin module for Hex-Rays can still work
### regardless of whether or not the "ida_hexrays" module exists.
class ida_hexrays_types(object):
    """
    This class is just the types from the "ida_hexrays" module and
    is used when defining multi-cased functions. Each of these need
    to be types in order to for the functions to be matched correctly.
    If the type doesn't exist (as per "ida_hexrays_template), then we
    return a `callable` so that the type matching still sorta works.
    """
    Fget_type_from_module = lambda module, name: (lambda value: value if isinstance(value, type) else callable)(getattr(module, name))
    cexpr_t             = Fget_type_from_module(ida_hexrays, 'cexpr_t')
    cfuncptr_t          = Fget_type_from_module(ida_hexrays, 'cfuncptr_t')
    cfunc_t             = Fget_type_from_module(ida_hexrays, 'cfunc_t')
    cinsn_t             = Fget_type_from_module(ida_hexrays, 'cinsn_t')
    citem_t             = Fget_type_from_module(ida_hexrays, 'citem_t')
    cnumber_t           = Fget_type_from_module(ida_hexrays, 'cnumber_t')
    ctree_item_t        = Fget_type_from_module(ida_hexrays, 'ctree_item_t')
    gco_info_t          = Fget_type_from_module(ida_hexrays, 'gco_info_t')
    hexrays_failure_t   = Fget_type_from_module(ida_hexrays, 'hexrays_failure_t')
    ivlset_t            = Fget_type_from_module(ida_hexrays, 'ivlset_t')
    lvar_locator_t      = Fget_type_from_module(ida_hexrays, 'lvar_locator_t')
    lvar_ref_t          = Fget_type_from_module(ida_hexrays, 'lvar_ref_t')
    lvar_saved_info_t   = Fget_type_from_module(ida_hexrays, 'lvar_saved_info_t')
    lvars_t             = Fget_type_from_module(ida_hexrays, 'lvars_t')
    lvar_t              = Fget_type_from_module(ida_hexrays, 'lvar_t')
    mba_ranges_t        = Fget_type_from_module(ida_hexrays, 'mba_ranges_t')
    mba_t               = Fget_type_from_module(ida_hexrays, 'mba_t')
    mblock_t            = Fget_type_from_module(ida_hexrays, 'mblock_t')
    minsn_t             = Fget_type_from_module(ida_hexrays, 'minsn_t')
    mlist_t             = Fget_type_from_module(ida_hexrays, 'mlist_t')
    mop_t               = Fget_type_from_module(ida_hexrays, 'mop_t')
    op_parent_info_t    = Fget_type_from_module(ida_hexrays, 'op_parent_info_t')
    rlist_t             = Fget_type_from_module(ida_hexrays, 'rlist_t')
    stkvar_ref_t        = Fget_type_from_module(ida_hexrays, 'stkvar_ref_t')
    treeloc_t           = Fget_type_from_module(ida_hexrays, 'treeloc_t')
    var_ref_t           = Fget_type_from_module(ida_hexrays, 'var_ref_t')
    vdloc_t             = Fget_type_from_module(ida_hexrays, 'vdloc_t')
    vivl_t              = Fget_type_from_module(ida_hexrays, 'vivl_t')
    voff_t              = Fget_type_from_module(ida_hexrays, 'voff_t')
    del(Fget_type_from_module)

class region(object):
    """
    This namespace is for interacting with regions from Hex-Rays.
    Since regions aren't available in older versions of Hex-Rays,
    we include a number of utilities in case they are necessary.
    """

    __descriptions = {getattr(ida_hexrays, attribute) : attribute for attribute in dir(ida_hexrays) if attribute.startswith('MMIDX_')}
    __descriptions[ida_hexrays.MMIDX_GLBHIGH] = 'global'
    __descriptions[ida_hexrays.MMIDX_GLBLOW] = 'bottom-stack'

    @classmethod
    def format(cls, index):
        '''Return the description of the region specified by `index` as a string.'''
        descriptions = cls.__descriptions
        if index in descriptions:
            return "{:s}({:d})".format(descriptions.get(index), index)
        return "{:#x}".format(index)

class variables(object):
    """
    This namespace contains utilities that are related to the local
    variables from a function produced by the decompiler. Generally,
    it tries to avoid dealing with both the ``ida_hexrays.lvar_t`` and
    ``ida_hexrays.lvars_t`` types since both of them can become de-scoped
    when the microcode for the function they belong to is refreshed.

    This is an internal namespace and is intended to be similar
    to the contents of the ``internal.interface`` module.
    """

    @classmethod
    def copy_vdloc(cls, atype, alocinfo):
        '''Return a new instance of ``ida_hexrays.vdloc_t`` using the given `atype` and `alocinfo`.'''
        result = ida_hexrays.vdloc_t()
        if atype in {idaapi.ALOC_REG1}:
            result.set_reg1(alocinfo & 0x0000FFFF)

        elif atype in {idaapi.ALOC_STATIC}:
            result.set_ea(alocinfo)

        elif atype in {idaapi.ALOC_STACK}:
            result.set_stkoff(alocinfo)

        elif atype in {idaapi.ALOC_RREL}:
            rrel = idaapi.rrel_t()
            rrel.reg, rrel.off = alocinfo
            result.consume_rrel(rrel)

        # If the type is ALOC_DIST, then we need to recurse for each of its members.
        elif atype in {idaapi.ALOC_DIST}:
            assert(isinstance(alocinfo, types.ordered))
            scattered_aloc = idaapi.scattered_aloc_t()
            for satype, (item, offset, size) in alocinfo:
                vdloc = cls.copy_vdloc(satype, item)
                argpart = idaapi.argpart_t(vdloc)
                argpart.off, argpart.size = offset, size
                scattered_aloc.push_back(argpart)
            result.consume_scattered(scattered_aloc)

        else:
            ltypes = {getattr(idaapi, attribute) : attribute for attribute in dir(idaapi) if attribute.startswith('ALOC_')}
            raise exceptions.InvalidTypeOrValueError(u"{:s}.copy_vdloc({:d}, {!r}) : Unable to duplicate a location of type {:s} for the specified location information ({!r}).".format('.'.join([__name__, cls.__name__]), atype, alocinfo, "{:s}({:d})".format(ltypes[atype], atype) if atype in ltypes else "{:d}".format(atype), alocinfo))
        return result

    @classmethod
    def new_locator(cls, ea, location):
        '''Return the ``ida_hexrays.lvar_locator_t`` for a variable defined at the address `ea` using the given `location` as its type.'''
        atype, alocinfo = location.atype(), interface.tinfo.location_raw(location)
        if atype == idaapi.ALOC_REG2:
            ltypes = {getattr(idaapi, attribute) : attribute for attribute in dir(idaapi) if attribute.startswith('ALOC_')}
            raise exceptions.InvalidTypeOrValueError(u"{:s}.new_locator({:#x}, {!r}) : Unable to create a locator for the variable at address {:#x} using an unsupported type {:s}.".format('.'.join([__name__, cls.__name__]), ea, location, ea, "{:s}({:d})".format(ltypes[atype], atype) if atype in ltypes else "{:d}".format(atype)))

        # use the location info that we extracted with interface.tinfo, and
        # use its result  to create a new instance of the decompiler's vdloc_t.
        vdloc = cls.copy_vdloc(*alocinfo)
        return ida_hexrays.lvar_locator_t(vdloc, ea)

    @classmethod
    def get_locator(cls, reference):
        '''Return the ``ida_hexrays.lvar_locator_t`` for the variable described by the specified `reference`.'''
        types = ida_hexrays_types.lvar_ref_t, ida_hexrays_types.var_ref_t, ida_hexrays_types.lvar_t, ida_hexrays_types.lvar_locator_t
        if not isinstance(reference, types):
            raise exceptions.InvalidTypeOrValueError(u"{:s}.get_locator({!r}) : Unable to fetch the variable locator from the requested reference ({!r}) due to it being an unsupported type {:s}.".format('.'.join([__name__, cls.__name__]), reference, reference, utils.pycompat.fullname(reference.__class__)))

        elif isinstance(reference, ida_hexrays_types.lvar_locator_t):
            return cls.new_locator(reference.defea, reference.location)

        # extract the lvar_t from the reference, and use it to create a
        # completely new (and hopefully safe) instance of lvar_locator_t.
        lvar = reference if isinstance(reference, ida_hexrays_types.lvar_t) else reference.getv()
        return cls.new_locator(lvar.defea, lvar.location)

    @classmethod
    def identity(cls, locator):
        '''Return a unique identity that can be used in comparisons for the ``ida_hexrays.lvar_locator_t`` specified by `locator`.'''
        ea, vdloc = locator.defea, locator.location
        atype, alocinfo = interface.tinfo.location_raw(vdloc)
        if isinstance(alocinfo, internal.types.list):
            return ea, atype, tuple(alocinfo)
        return ea, atype, alocinfo

class function(object):
    """
    This namespace contains tools for a function that is produced by the
    decompiler. It intends to consolidate support for ``ida_hexrays.cfunc_t``,
    ``ida_hexrays.cfuncptr_t``, ``idaapi.func_t``, and addresses. This is
    similar to the ``internal.interface.function`` namespace and its only
    difference is that it acts on output from the decompiler.

    This is an internal namespace and is intended to be similar to the
    contents of the ``internal.interface`` module.
    """

    @classmethod
    def by_address(cls, ea, *flags):
        '''Decompile the function at the address `ea` with the given `flags` and return an ``idaapi.cfuncptr_t``.'''
        if not interface.function.has(int(ea)):
            raise interface.function.missing(int(ea), caller=['hexrays', 'function', 'by_address'])

        [flags] = flags if flags else [{getattr(ida_hexrays, attribute, 0) for attribute in ['DECOMP_NO_WAIT', 'DECOMP_NO_XREFS']}]
        failure, defaults = ida_hexrays.hexrays_failure_t(), functools.reduce(operator.or_, flags)

        fn, argcount = int(ea), utils.pycompat.code.argcount(utils.pycompat.function.code(ida_hexrays.decompile))
        res = ida_hexrays.decompile(fn, failure) if argcount < 3 else ida_hexrays.decompile(fn, failure, defaults)
        if res is None:
            raise exceptions.DisassemblerError(u"{:s}.by_address({:#x}, {:#x}): Unable to decompile function due to error {:#x} at address {:#x} ({:s}).".format('.'.join([__name__, 'function']), ea, defaults, failure.code, failure.errea, utils.string.of(failure.desc())))
        return res

    @classmethod
    def by_function(cls, func, *flags):
        '''Decompile the function specified in `func` with the given `flags` and return an ``idaapi.cfuncptr_t``.'''
        if not hasattr(ida_hexrays, 'decompile_func'):
            ea = cls.address(func)
            return cls.by_address(ea, *flags)

        [flags] = flags if flags else [{getattr(ida_hexrays, attribute, 0) for attribute in ['DECOMP_NO_WAIT', 'DECOMP_NO_XREFS']}]
        failure, defaults = ida_hexrays.hexrays_failure_t(), functools.reduce(operator.or_, flags)

        res = ida_hexrays.decompile_func(func, failure, defaults)
        if res is None:
            ea = cls.address(func)
            raise exceptions.DisassemblerError(u"{:s}.by_function({:#x}, {:#x}): Unable to decompile function due to error {:#x} at address {:#x} ({:s}).".format('.'.join([__name__, 'function']), ea, defaults, failure.code, failure.errea, utils.string.of(failure.desc())))
        return res

    @classmethod
    def by(cls, function, *flags):
        '''Decompile the specified `function` using the given `flags` and return an ``idaapi.cfuncptr_t``.'''
        fn = function.entry_ea if isinstance(function, (ida_hexrays_types.cfuncptr_t, ida_hexrays_types.cfunc_t, ida_hexrays_types.mba_t)) else function
        return cls.by_function(fn) if isinstance(fn, idaapi.func_t) else cls.by_address(fn)

    @classmethod
    def address(cls, function):
        '''Return the address of the entry point for the given `function`.'''
        res = function.entry_ea if isinstance(function, (ida_hexrays_types.cfuncptr_t, ida_hexrays_types.cfunc_t, ida_hexrays_types.mba_t)) else function
        fn = res if isinstance(res, idaapi.func_t) else idaapi.get_func(int(res))
        if not fn:
            raise interface.function.missing(res, caller=['hexrays', 'function', 'address'])
        return interface.range.start(fn)

    @classmethod
    def has(cls, function):
        '''Return if the `function` has been cached by the decompiler.'''
        ea = cls.address(function)
        return ida_hexrays.has_cached_cfunc(ea)

    @classmethod
    def clear(cls, function):
        '''Clear the decompiler cache for the given `function`.'''
        ea = cls.address(function)
        return ida_hexrays.mark_cfunc_dirty(ea)

    @classmethod
    def user_comments(cls, comments):
        '''Yield each user-defined label belonging to the specified `comments`.'''
        user_cmts = comments
        for treeloc, citem in user_cmts.items():
            ea, itp, used = treeloc.ea, treeloc.itp, citem.used
            string = citem.c_str()
            yield ea, itp, utils.string.of(string)
        return

    @classmethod
    def user_iterate(cls, user, Fstart, Fnext, Fend, Ffirst, Fsecond):
        '''Yield each key and value for the specified `user`-defined members using the given callables.'''
        iterator, end = Fstart(user), Fend(user)
        while iterator.x != end.x:
            key, value = Ffirst(iterator), Fsecond(iterator)
            yield key, value
        return

    @classmethod
    def user_labels(cls, labels):
        '''Yield each user-defined label belonging to the specified `labels`.'''
        Fstart, Fend = ida_hexrays.user_labels_begin, ida_hexrays.user_labels_end
        Fnext = ida_hexrays.user_labels_next
        Ffirst, Fsecond = ida_hexrays.user_labels_first, ida_hexrays.user_labels_second
        return cls.user_iterate(labels, Fstart, Fnext, Fend, Ffirst, Fsecond)

    #@classmethod
    #def user_formats(cls, formats):
    #    '''Yield each user-defined number format belonging to the specified `formats`.'''
    #    Fstart, Fend = ida_hexrays.user_numforms_begin, ida_hexrays.user_numforms_end
    #    Fnext = ida_hexrays.user_numforms_next
    #    Ffirst, Fsecond = ida_hexrays.user_numforms_first, ida_hexrays.user_numforms_second
    #    iterable = cls.user_iterate(formats, Fstart, Fnext, Fend, Ffirst, Fsecond)
    #    return ((oploc.ea, oploc.opnum, format) for oploc, format in iterable)

    @classmethod
    def user_itemflags(cls, itemflags):
        '''Yield each user-defined item flag belonging to the specified `itemflags`.'''
        Fstart, Fend = ida_hexrays.user_iflags_begin, ida_hexrays.user_iflags_end
        Fnext = ida_hexrays.user_iflags_next
        Ffirst, Fsecond = ida_hexrays.user_iflags_first, ida_hexrays.user_iflags_second
        iterable = cls.user_iterate(itemflags, Fstart, Fnext, Fend, Ffirst, Fsecond)
        return ((iloc.ea, iloc.op, iflags) for iloc, iflags in iterable)

    @classmethod
    def user_unions(cls, unions):
        '''Yield each user-selected union member belonging to the specified `unions`.'''
        Fstart, Fend = ida_hexrays.user_unions_begin, ida_hexrays.user_unions_end
        Fnext = ida_hexrays.user_unions_next
        Ffirst, Fsecond = ida_hexrays.user_unions_first, ida_hexrays.user_unions_second
        iterable = cls.user_iterate(unions, Fstart, Fnext, Fend, Ffirst, Fsecond)
        return ((ea, [intvec[index] for index in range(intvec.size())]) for ea, intvec in iterable)

    @classmethod
    def comments(cls, cfunc):
        '''Yield each of the user-defined comments belonging to the decompiled function represented by `cfunc`.'''
        return cls.user_comments(cfunc.user_cmts)

    @classmethod
    def labels(cls, cfunc):
        '''Yield each of the user-defined labels belonging to the decompiled function represented by `cfunc`.'''
        return cls.user_labels(cfunc.user_labels)

    @classmethod
    def itemflags(cls, cfunc):
        '''Yield each of the user-defined item flags belonging to the decompiled function represented by `cfunc`.'''
        return cls.user_itemflags(cfunc.user_iflags)

    @classmethod
    def unions(cls, cfunc):
        '''Yield each of the user-selected unions belonging to the decompiled function represented by `cfunc`.'''
        return cls.user_unions(cfunc.user_unions)
