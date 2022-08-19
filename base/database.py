"""
Database module

This module exposes a number of tools that can be used on a database
and on addresses within the database. There are a number of namespaces
that allow one to query information about the database as a whole, or to
read/write to an address within the database.

The base argument type for many of the utilites within this module is
the address. This can allow one to modify the colors or comments for an
address, or to read/write from the different types of data that might
exist at an address.

Some namespaces are also provided for querying the available symbolic
information that IDA has discovered about a binary. This can be used
to search and navigate the database. Some of the available namespaces
that can be used for querying are ``functions``, ``segments``,
``names``, ``imports``, ``entries``, and ``marks``.
"""

import six, builtins

import functools, operator, itertools, types
import sys, os, logging, string, bisect
import math, codecs, array as _array, fnmatch, re, ctypes

import function, segment
import structure as _structure, instruction as _instruction
import ui, internal
from internal import utils, interface, exceptions as E

import idaapi

## properties
def here():
    '''Return the current address.'''
    return ui.current.address()
h = utils.alias(here)

@utils.multicase()
def within():
    '''Should always return true.'''
    return within(ui.current.address())
@utils.multicase(ea=six.integer_types)
def within(ea):
    '''Return true if address `ea` is within the bounds of the database.'''
    left, right = config.bounds()
    return left <= ea < right
contains = utils.alias(within)

def top():
    '''Return the very lowest address within the database.'''
    ea, _ = config.bounds()
    return ea
def bottom():
    '''Return the very highest address within the database.'''
    _, ea = config.bounds()
    return ea

class config(object):
    """
    This namespace contains various read-only properties about the
    database. This includes things such as the database boundaries,
    its filename, the path to the generated database, etc. Some tools
    for determining the type of the binary are also included.
    """

    # cache the default value for the structure
    info = idaapi.get_inf_structure()

    @classmethod
    def __init_info_structure__(cls, idp_modname):
        information = idaapi.get_inf_structure()
        if information:
            logging.debug(u"{:s}.__init_info_structure__({!s}) : Successfully fetched and cached information structure for database.".format('.'.join([__name__, cls.__name__]), utils.string.escape(idp_modname, '"')))

            # Display summary of the database and what it's used for.
            bits = "{:d}-bit".format(64 if information.is_64bit() else 32 if information.is_32bit() else 16)
            format = 'library' if information.lflags & idaapi.LFLG_IS_DLL else 'binary'

            if idaapi.__version__ < 7.0:
                byteorder = "{:s}-endian".format('big' if idaapi.cvar.inf.mf else 'little')
            else:
                byteorder = "{:s}-endian".format('big' if information.lflags & idaapi.LFLG_MSF else 'little')

            if idaapi.__version__ >= 7.0:
                mode = ' kernelspace' if information.lflags & idaapi.LFLG_KERNMODE else ' userspace'
            else:
                mode = ''
            logging.warning("Initialized {tag!s} database v{version:d} for {bits:s} {byteorder:s}{mode:s} {format:s}.".format('.'.join([information.__class__.__module__, information.__class__.__name__]), tag=information.tag, bits=bits, byteorder=byteorder, mode=mode, format=format, version=information.version))

        else:
            logging.fatal(u"{:s}.__init_info_structure__({!s}) : Unknown error while trying to get information structure for database.".format('.'.join([__name__, cls.__name__]), utils.string.escape(idp_modname, '"')))
        cls.info = information

    @classmethod
    def __nw_init_info_structure__(cls, nw_code, is_old_database):
        logging.debug(u"{:s}.__nw_init_info_structure__({!s}) : Received notification to initialize information structure for database.".format('.'.join([__name__, cls.__name__]), ', '.join(map("{!r}".format, [nw_code, is_old_database]))))
        idp_modname = idaapi.get_idp_name()
        return cls.__init_info_structure__(idp_modname)

    @utils.multicase()
    @classmethod
    def lflags(cls):
        '''Return the value of the ``idainfo.lflags`` field from the database.'''
        if idaapi.__version__ < 7.2:
            return cls.info.lflags
        return idaapi.inf_get_lflags()
    @utils.multicase(mask=six.integer_types)
    @classmethod
    def lflags(cls, mask):
        '''Return the value of the ``idainfo.lflags`` field from the database with the specified `mask`.'''
        if idaapi.__version__ < 7.2:
            return cls.info.lflags & mask
        return idaapi.inf_get_lflags() & mask
    @utils.multicase(mask=six.integer_types, value=six.integer_types)
    @classmethod
    def lflags(cls, mask, value):
        '''Set the ``idainfo.lflags`` with the provided `mask` from the database to the specified `value`.'''
        if idaapi.__version__ < 7.2:
            result, cls.info.lflags = cls.info.lflags, (result & ~mask) | (value & mask)
            return result

        # Newer versions of IDA use the idaapi.inf_get_lflags() function.
        result = idaapi.inf_get_lflags()
        if not idaapi.inf_set_lflags((result & ~mask) | (value & mask)):
            raise E.DisassemblerError(u"{:s}.lflags({:#x}, {:#x}) : Unable to modify the flags in idainfo.lflags ({:#x} & {:#x}) to the specified value ({:s}).".format('.'.join([__name__, cls.__name__]), result, mask, "{:#x} & {:#x}".format(value, mask) if value & ~mask else "{:#x}".format(value)))
        return result

    @classmethod
    def filename(cls):
        '''Return the filename that the database was built from.'''
        res = idaapi.get_root_filename()
        return utils.string.of(res)

    @classmethod
    def idb(cls):
        '''Return the full path to the database.'''
        res = idaapi.cvar.database_idb if idaapi.__version__ < 7.0 else idaapi.get_path(idaapi.PATH_TYPE_IDB)
        res = utils.string.of(res)
        return res.replace(os.sep, '/')
    database = utils.alias(idb, 'config')

    @classmethod
    def module(cls):
        '''Return the module name as per the windows loader.'''
        res = cls.filename()
        res = os.path.split(res)
        return os.path.splitext(res[1])[0]

    @utils.multicase()
    @classmethod
    def path(cls):
        '''Return the absolute path to the directory containing the database.'''
        res = cls.idb()
        path, _ = os.path.split(res)
        return path
    @utils.multicase(pathname=six.string_types)
    @classmethod
    def path(cls, pathname, *components):
        '''Return an absolute path composed of the provided `pathname` and any additional `components` relative to the directory containing the database.'''
        res = cls.idb()
        path, _ = os.path.split(res)
        return os.path.join(path, pathname, *components)

    @classmethod
    def baseaddress(cls):
        '''Return the baseaddress of the database.'''
        return idaapi.get_imagebase()

    @classmethod
    def is_readonly(cls):
        '''Return whether the database is read-only or not.'''
        if idaapi.__version__ < 7.0:
            raise E.UnsupportedVersion(u"{:s}.readonly() : This function is only supported on versions of IDA 7.0 and newer.".format('.'.join([__name__, cls.__name__])))
        elif idaapi.__version__ < 7.2:
            return cls.info.readonly_idb()
        return idaapi.inf_readonly_idb()
    readonlyQ = utils.alias(is_readonly, 'config')

    @classmethod
    def is_sharedobject(cls):
        '''Return whether the database is a shared-object or not.'''
        if idaapi.__version__ < 7.0:
            raise E.UnsupportedVersion(u"{:s}.is_sharedobject() : This function is only supported on versions of IDA 7.0 and newer.".format('.'.join([__name__, cls.__name__])))
        return True if cls.lflags(idaapi.LFLG_IS_DLL) else False
    sharedobject = is_shared = sharedQ = utils.alias(is_sharedobject, 'config')

    @classmethod
    def is_kernelspace(cls):
        '''Return whether the database is using a kernelmode address space or not.'''
        if idaapi.__version__ < 7.0:
            raise E.UnsupportedVersion(u"{:s}.is_kernelspace() : This function is only supported on versions of IDA 7.0 and newer.".format('.'.join([__name__, cls.__name__])))
        return True if cls.lflags(idaapi.LFLG_KERNMODE) else False
    kernelspaceQ = kernelQ = utils.alias(is_kernelspace, 'config')

    @utils.multicase()
    @classmethod
    def filetype(cls):
        '''Return the file type identified by the loader when creating the database.'''
        if idaapi.__version__ < 7.2:
            return cls.info.filetype
        return idaapi.inf_get_filetype()
    @utils.multicase(filetype_t=six.integer_types)
    @classmethod
    def filetype(cls, filetype_t):
        '''Set the file type identified by the loader to the specified `filetype_t`.'''
        if idaapi.__version__ < 7.2:
            result, cls.info.filetype = cls.info.filetype, filetype_t
            return result

        # Newer versions of IDA use the idaapi.inf_get_filetype() and idaapi.inf_set_filetype() functions.
        result = idaapi.inf_get_filetype()
        if not idaapi.inf_set_filetype(filetype_t):
            raise E.DisassemblerError(u"{:s}.filetype({:#x}) : Unable to set value for idainfo.filetype to the specified value ({:#x}).".format('.'.join([__name__, cls.__name__]), filetype_t, filetype_t))
        return result
    @utils.multicase(FT_=six.string_types)
    @classmethod
    def filetype(cls, FT_):
        '''Set the file type identified by the loader to the value for the string `FT_`.'''
        prefix, choice = 'FT_', FT_.upper()
        candidates = {prefix + choice, choice}

        # Grab all of our available choices from the idc module since they're not defined anywhere else.
        import idc
        filtered = ((name, getattr(idc, name)) for name in dir(idc) if name.startswith(prefix))
        choices = {item : value for item, value in filtered if isinstance(value, six.integer_types)}

        # Find a valid choice by iterating through each one and seeing if its in our list of candidates.
        iterable = (value for item, value in choices.items() if item in candidates)
        value = builtins.next(iterable, None)
        if value is None:
            raise E.ItemNotFoundError(u"{:s}.filetype({!r}) : Unable to find the requested file type ({!r}) in the list of choices.".format('.'.join([__name__, cls.__name__]), FT_, string))

        # We found it, so we can recurse into the correct case to assign it.
        return cls.filetype(value)

    @utils.multicase()
    @classmethod
    def ostype(cls):
        '''Return the operating system type identified by the loader when creating the database.'''
        # FIXME: this is a bitflag that should be documented in libfuncs.hpp
        #        which unfortunately is not included anywhere in the sdk.
        if idaapi.__version__ < 7.2:
            return cls.info.ostype
        return idaapi.inf_get_ostype()
    @utils.multicase(ostype_t=six.integer_types)
    @classmethod
    def ostype(cls, ostype_t):
        '''Set the operating system type for the database to the specified `ostype_t`.'''
        if idaapi.__version__ < 7.2:
            result, cls.info.ostype = cls.info.ostype, ostype_t
            return result

        # Newer versions of IDA use the idaapi.inf_get_filetype() and idaapi.inf_set_filetype() functions.
        result = idaapi.inf_get_ostype()
        if not idaapi.inf_set_ostype(ostype_t):
            raise E.DisassemblerError(u"{:s}.ostype({:#x}) : Unable to set value for idainfo.ostype to the specified value ({:#x}).".format('.'.join([__name__, cls.__name__]), ostype_t, ostype_t))
        return result
    @utils.multicase(OSTYPE_=six.string_types)
    @classmethod
    def ostype(cls, OSTYPE_):
        '''Set the operating system type for the database to the value for the string `OSTYPE_`.'''
        prefix, choice = 'OSTYPE_', OSTYPE_.upper()
        candidates = {prefix + choice, choice}

        # Grab all of our available choices from the idc module since they're not defined anywhere else.
        import idc
        filtered = ((name, getattr(idc, name)) for name in dir(idc) if name.startswith(prefix))
        choices = {item : value for item, value in filtered if isinstance(value, six.integer_types)}

        # Find a valid choice by iterating through each one and seeing if its in our list of candidates.
        iterable = (value for item, value in choices.items() if item in candidates)
        value = builtins.next(iterable, None)
        if value is None:
            raise E.ItemNotFoundError(u"{:s}.ostype({!r}) : Unable to find the requested operating system type ({!r}) in the list of choices.".format('.'.join([__name__, cls.__name__]), OSTYPE_, string))

        # We found it, so we can recurse into the correct case to assign it.
        return cls.ostype(value)

    @utils.multicase()
    @classmethod
    def apptype(cls):
        '''Return the application type identified by the loader when creating the database.'''
        # FIXME: this is a bitflag that should be documented in libfuncs.hpp
        #        which unfortunately is not included anywhere in the sdk.
        if idaapi.__version__ < 7.2:
            return cls.info.apptype
        return idaapi.inf_get_apptype()
    @utils.multicase(apptype_t=six.integer_types)
    @classmethod
    def apptype(cls, apptype_t):
        '''Set the application type for the database to the specified `apptype_t`.'''
        if idaapi.__version__ < 7.2:
            result, cls.info.apptype = cls.info.ostype, apptype_t
            return result

        # Newer versions of IDA use the idaapi.inf_get_filetype() and idaapi.inf_set_filetype() functions.
        result = idaapi.inf_get_apptype()
        if not idaapi.inf_set_apptype(apptype_t):
            raise E.DisassemblerError(u"{:s}.apptype({:#x}) : Unable to set value for idainfo.apptype to the specified value ({:#x}).".format('.'.join([__name__, cls.__name__]), apptype_t, apptype_t))
        return result
    @utils.multicase(APPT_=six.string_types)
    @classmethod
    def apptype(cls, APPT_):
        '''Set the application type for the database to the value for the string `APPT_`.'''
        prefix, choice = 'APPT_', APPT_.upper()
        candidates = {prefix + choice, choice}

        # Grab all of our available choices from the idc module since they're not defined anywhere else.
        import idc
        filtered = ((name, getattr(idc, name)) for name in dir(idc) if name.startswith(prefix))
        choices = {item : value for item, value in filtered if isinstance(value, six.integer_types)}

        # Find a valid choice by iterating through each one and seeing if its in our list of candidates.
        iterable = (value for item, value in choices.items() if item in candidates)
        value = builtins.next(iterable, None)
        if value is None:
            raise E.ItemNotFoundError(u"{:s}.apptype({!r}) : Unable to find the requested application type ({!r}) in the list of choices.".format('.'.join([__name__, cls.__name__]), APPT_, string))

        # We found it, so we can recurse into the correct case to assign it.
        return cls.apptype(value)

    @classmethod
    def changes(cls):
        '''Return the number of changes within the database.'''
        if idaapi.__version__ < 7.0:
            raise E.UnsupportedVersion(u"{:s}.changes() : This function is only supported on versions of IDA 7.0 and newer.".format('.'.join([__name__, cls.__name__])))
        elif idaapi.__version__ < 7.2:
            return cls.info.database_change_count
        return idaapi.inf_get_database_change_count()

    @classmethod
    def processor(cls):
        '''Return the name of the processor used by the database.'''
        if idaapi.__version__ < 7.0:
            raise E.UnsupportedVersion(u"{:s}.processor() : This function is only supported on versions of IDA 7.0 and newer.".format('.'.join([__name__, cls.__name__])))
        elif hasattr(cls.info, 'procName'):
            result = cls.info.procName
        else:
            result = idaapi.inf_get_procname()
        return utils.string.of(result)

    @classmethod
    def compiler(cls):
        '''Return the compiler that was configured for the database.'''
        if idaapi.__version__ < 7.2:
            return cls.info.cc

        # Newer versions of IDA use the idaapi.inf_get_cc() function.
        cc = idaapi.compiler_info_t()
        if not idaapi.inf_get_cc(cc):
            raise E.DisassemblerError(u"{:s}.processor() : Unable to fetch the value for the idainfo.cc attribute.".format('.'.join([__name__, cls.__name__])))
        return cc
    @classmethod
    def version(cls):
        '''Return the version of the database.'''
        if idaapi.__version__ < 7.2:
            return cls.info.version
        return idaapi.inf_get_version()

    @classmethod
    def type(cls, typestr):
        '''Evaluates a type string and returns its size according to the compiler used by the database.'''
        lookup = {
            'bool': 'size_b',
            'short': 'size_s',
            'int': 'size_i', 'float': 'size_l', 'single': 'size_l',
            'long': 'size_l',
            'longlong': 'size_ll', 'double': 'size_ll',
            'enum': 'size_e',
            'longdouble': 'size_ldbl',
            'align': 'defalign', 'alignment': 'defalign',
        }
        string = typestr.replace(' ', '')
        return getattr(cls.compiler(), lookup.get(string.lower(), typestr.lower()))

    @classmethod
    def bits(cls):
        '''Return number of bits of the processor used by the database.'''
        result = cls.lflags(idaapi.LFLG_PC_FLAT | idaapi.LFLG_64BIT)
        if result & idaapi.LFLG_64BIT:
            return 64
        elif result & idaapi.LFLG_PC_FLAT:
            return 32
        return 32 if result & idaapi.LFLG_FLAT_OFF32 else 16

    @classmethod
    def size(cls):
        '''Return the number of bytes used by the database which can be used to distinguish whether you're running 32-bit or 64-bit.'''
        import ida_typeinf

        # This is a trick gifted by me by rolfr through his comprehensive
        # knowledge of IDA internals in order to get this attribute in the
        # exact way that IDA does it. We use the ida_typeinf module instead
        # of idaapi in order to preserve this tech throughout history in the
        # way it was bestowed upon us...

        tif = ida_typeinf.tinfo_t()
        tif.create_ptr(ida_typeinf.tinfo_t(ida_typeinf.BT_VOID))
        return tif.get_size()

    @classmethod
    def bitsize(cls):
        '''Return the number of bits used by the database.'''
        return 8 * cls.size()

    @classmethod
    def byteorder(cls):
        '''Return a string representing the byte-order used by integers in the database.'''
        if idaapi.__version__ < 7.0:
            res = idaapi.cvar.inf.mf
            return 'big' if res else 'little'
        return 'big' if cls.lflags(idaapi.LFLG_MSF) else 'little'

    @classmethod
    def main(cls):
        if idaapi.__version__ < 7.2:
            return cls.info.main
        return idaapi.inf_get_main()

    @classmethod
    def entry(cls):
        '''Return the first entry point for the database.'''
        if idaapi.__version__ < 7.2:
            return cls.info.start_ea
        return idaapi.inf_get_start_ea()

    @classmethod
    def margin(cls):
        '''Return the current margin position for the current database.'''
        return cls.info.margin if idaapi.__version__ < 7.2 else idaapi.inf_get_margin()

    @classmethod
    def bounds(cls):
        '''Return the bounds of the current database in a tuple formatted as `(left, right)`.'''
        if idaapi.__version__ < 7.2:
            min, max = cls.info.minEA, cls.info.maxEA
        else:
            min, max = idaapi.inf_get_min_ea(), idaapi.inf_get_max_ea()
        return interface.bounds_t(min, max)

    class register(object):
        """
        This namespace returns the available register names and their
        sizes for the database.
        """
        @classmethod
        def names(cls):
            '''Return all of the register names in the database.'''
            names = idaapi.ph_get_regnames()
            return [utils.string.of(item) for item in names]
        @classmethod
        def segments(cls):
            '''Return all of the segment registers in the database.'''
            sreg_first, sreg_last = (idaapi.ph_get_regFirstSreg, idaapi.ph_get_regLastSreg) if idaapi.__version__ < 7.0 else (idaapi.ph_get_reg_first_sreg, idaapi.ph_get_reg_last_sreg)

            names = cls.names()
            return [names[ri] for ri in builtins.range(sreg_first(), 1 + sreg_last())]
        @classmethod
        def codesegment(cls):
            '''Return all of the code segment registers in the database.'''
            res = idaapi.ph_get_regCodeSreg() if idaapi.__version__ < 7.0 else idaapi.ph_get_reg_code_sreg()
            return cls.names()[res]
        @classmethod
        def datasegment(cls):
            '''Return all of the data segment registers in the database.'''
            res = idaapi.ph_get_regDataSreg() if idaapi.__version__ < 7.0 else idaapi.ph_get_reg_data_sreg()
            return cls.names()[res]
        @classmethod
        def segmentbits(cls):
            '''Return the segment register size for the database.'''
            return 8 * idaapi.ph_get_segreg_size()

range = utils.alias(config.bounds, 'config')
filename, idb, module, path = utils.alias(config.filename, 'config'), utils.alias(config.idb, 'config'), utils.alias(config.module, 'config'), utils.alias(config.path, 'config')
path = utils.alias(config.path, 'config')
baseaddress = base = utils.alias(config.baseaddress, 'config')

class functions(object):
    r"""
    This namespace is used for listing all the functions inside the
    database. By default a list is returned containing the address of
    each function.

    When listing functions that are matched, the following legend can be
    used to identify certain characteristics about them:

        `+` - The function has an implicit tag (named or typed)
        `*` - The function has been explicitly tagged
        `J` - The function is a wrapper or a thunk
        `L` - The function was pattern matched as a library
        `S` - The function is declared statically
        `^` - The function does not contain a frame
        `?` - The function has its stack points calculated incorrectly and may be incorrect
        `T` - The function has a prototype that was applied to it manually or via decompilation
        `t` - The function has a prototype that was guessed
        `D` - The function has been previously decompiled

    The different types that one can match functions with are the following:

        `address` or `ea` - Match according to the function's address
        `name` - Match according to the exact name
        `like` - Filter the function names according to a glob
        `regex` - Filter the function names according to a regular-expression
        `typed` - Filter the functions for any that have type information applied to them
        `decompiled` - Filter the functions for any that have been decompiled
        `frame` - Filter the functions for any that contain a frame
        `problems` - Filter the functions for any that contain problems with their stack
        `library` - Filter the functions that any which were detected as a library function
        `wrapper` - Filter the functions that are flagged as wrappers (thunks)
        `exceptions` Filter the functions for any that either handles an exception or sets up a handler
        `tagged` - Filter the functions for any that use the specified tag(s)
        `predicate` - Filter the functions by passing their ``idaapi.func_t`` to a callable

    Some examples of how to use these keywords are as follows::

        > for ea in database.functions(): ...
        > database.functions.list('*sub*')
        > iterable = database.functions.iterate(regex='.*alloc')
        > result = database.functions.search(like='*alloc*')

    """
    __matcher__ = utils.matcher()
    __matcher__.boolean('name', lambda name, item: name.lower() == item.lower(), function.by, function.name)
    __matcher__.combinator('like', utils.fcompose(fnmatch.translate, utils.fpartial(re.compile, flags=re.IGNORECASE), operator.attrgetter('match')), function.by, function.name)
    __matcher__.combinator('regex', utils.fcompose(utils.fpartial(re.compile, flags=re.IGNORECASE), operator.attrgetter('match')), function.by, function.name)
    __matcher__.boolean('address', function.contains), __matcher__.boolean('ea', function.contains)
    __matcher__.mapping('typed', operator.truth, function.top, lambda ea: idaapi.get_tinfo2(ea, idaapi.tinfo_t()) if idaapi.__version__ < 7.0 else idaapi.get_tinfo(idaapi.tinfo_t(), ea))
    __matcher__.mapping('decompiled', operator.truth, function.type.is_decompiled)
    __matcher__.mapping('frame', operator.truth, function.type.has_frame)
    __matcher__.mapping('library', operator.truth, function.by, operator.attrgetter('flags'), utils.fpartial(operator.and_, idaapi.FUNC_LIB))
    __matcher__.mapping('wrapper', operator.truth, function.by, operator.attrgetter('flags'), utils.fpartial(operator.and_, idaapi.FUNC_THUNK))
    __matcher__.boolean('tagged', lambda parameter, keys: operator.truth(keys) == parameter if isinstance(parameter, bool) else operator.contains(keys, parameter) if isinstance(parameter, six.string_types) else keys&parameter, function.top, function.tag, operator.methodcaller('keys'), builtins.set)
    __matcher__.predicate('predicate', function.by)
    __matcher__.predicate('pred', function.by)

    if any(hasattr(idaapi, item) for item in ['is_problem_present', 'QueueIsPresent']):
        __matcher__.mapping('problems', operator.truth, function.top, utils.frpartial(function.type.has_problem, getattr(idaapi, 'PR_BADSTACK', 0xb)))

    if all(hasattr(idaapi, Fname) for Fname in ['tryblks_t', 'get_tryblks']):
        __matcher__.mapping('exceptions', operator.truth, function.by, lambda fn: idaapi.get_tryblks(idaapi.tryblks_t(), fn), utils.fpartial(operator.ne, 0))

    # chunk matching
    #__matcher__.boolean('greater', operator.le, utils.fcompose(function.chunks, functools.partial(map, builtins.list, operator.itemgetter(-1)), max)), __matcher__.boolean('gt', operator.lt, utils.fcompose(function.chunks, functools.partial(map, builtins.list, operator.itemgetter(-1)), max))
    #__matcher__.boolean('less', operator.ge, utils.fcompose(function.chunks, functools.partial(map, builtins.list, operator.itemgetter(0)), min)), __matcher__.boolean('lt', operator.gt, utils.fcompose(function.chunks, functools.partial(map, builtins.list, operator.itemgetter(0)), min))

    # entry point matching
    __matcher__.boolean('greater', operator.le, function.top), __matcher__.boolean('gt', operator.lt, function.top)
    __matcher__.boolean('less', operator.ge, function.top), __matcher__.boolean('lt', operator.gt, function.top)

    def __new__(cls):
        '''Return a list of all of the functions in the current database.'''
        return [item for item in cls.__iterate__()]

    @utils.multicase()
    @classmethod
    def __iterate__(cls):
        '''Iterates through all of the functions in the current database (ripped from idautils).'''
        left, right = config.bounds()

        # find first function chunk
        ch = idaapi.get_fchunk(left) or idaapi.get_next_fchunk(left)
        while ch and interface.range.start(ch) < right and (ch.flags & idaapi.FUNC_TAIL) != 0:
            ui.navigation.procedure(interface.range.start(ch))
            ch = idaapi.get_next_fchunk(interface.range.start(ch))

        # iterate through the rest of the functions in the database
        while ch and interface.range.start(ch) < right:
            ui.navigation.procedure(interface.range.start(ch))
            if function.within(interface.range.start(ch)):
                yield interface.range.start(ch)
            ch = idaapi.get_next_func(interface.range.start(ch))
        return

    @utils.multicase(string=six.string_types)
    @classmethod
    @utils.string.decorate_arguments('string')
    def iterate(cls, string):
        '''Iterate through all of the functions in the database with a glob that matches `string`.'''
        return cls.iterate(like=string)
    @utils.multicase()
    @classmethod
    @utils.string.decorate_arguments('name', 'like', 'regex')
    def iterate(cls, **type):
        '''Iterate through all of the functions in the database that match the keyword specified by `type`.'''
        iterable = cls.__iterate__()
        for key, value in (type or {'predicate': utils.fconstant(True)}).items():
            iterable = cls.__matcher__.match(key, value, iterable)
        for item in iterable: yield item

    @utils.multicase(string=six.string_types)
    @classmethod
    @utils.string.decorate_arguments('string')
    def list(cls, string):
        '''List all of the functions in the database with a glob that matches `string`.'''
        return cls.list(like=string)
    @utils.multicase()
    @classmethod
    @utils.string.decorate_arguments('name', 'like', 'regex')
    def list(cls, **type):
        '''List all of the functions in the database that match the keyword specified by `type`.'''
        listable = []

        # Some utility functions for grabbing counts of function attributes
        Fcount_lvars = utils.fcompose(function.frame.lvars, utils.count)
        Fcount_avars = utils.fcompose(function.frame.args.iterate, utils.count)

        # Set some reasonable defaults here
        maxentry = config.bounds()[0]
        maxaddr = minaddr = maxchunks = 0
        maxname = maxunmangled = chunks = marks = blocks = exits = 0
        lvars = avars = refs = 0

        # First pass through the list to grab the maximum lengths of the different fields
        for ea in cls.iterate(**type):
            func, _ = function.by(ea), ui.navigation.procedure(ea)
            maxentry = max(ea, maxentry)

            unmangled, realname = function.name(func), name(ea)
            maxname = max(len(unmangled), maxname)
            maxunmangled = max(len(unmangled), maxunmangled) if not internal.declaration.mangledQ(realname) else maxunmangled

            bounds, items = function.bounds(func), [item for item in function.chunks(func)]
            maxaddr, minaddr = max(max(bounds), maxaddr), max(min(bounds), minaddr)
            maxchunks = max(len(items), maxchunks)

            # Figure out the maximum values for each of these attributes
            blocks = max(len(builtins.list(function.blocks(func, silent=True))), blocks)
            exits = max(len(builtins.list(function.bottom(func))), exits)
            refs = max(len(xref.up(ea)), refs)
            lvars = max(Fcount_lvars(func) if idaapi.get_frame(ea) else 0, lvars)
            avars = max(Fcount_avars(func), avars)

            listable.append(ea)

        # Collect the number of digits for everything from the first pass
        cindex = utils.string.digits(len(listable), 10) if listable else 1
        try: cmaxoffset = utils.string.digits(offset(maxentry), 16)
        except E.OutOfBoundsError: cmaxoffset = 0
        cmaxentry, cmaxaddr, cminaddr = (utils.string.digits(item, 16) for item in [maxentry, maxaddr, minaddr])
        cchunks, cblocks, cexits, cavars, clvars, crefs = (utils.string.digits(item, 10) for item in [maxchunks, blocks, exits, avars, lvars, refs])

        # List all the fields of every single function that was matched
        for index, ea in enumerate(listable):
            func, decompiledQ = function.by(ui.navigation.procedure(ea)), interface.node.aflags(ui.navigation.procedure(ea), getattr(idaapi, 'AFL_HR_DETERMINED', 0xc0000000))
            tags = function.tag(ea)

            # any flags that might be useful
            ftagged = '-' if not tags else '*' if any(not item.startswith('__') for item in tags) else '+'
            ftyped = 'D' if function.type.is_decompiled(ea) else '-' if not function.type.has_typeinfo(func) else 'T' if interface.node.aflags(ea, idaapi.AFL_USERTI) else 't'
            fframe = '?' if function.type.has_problem(ea, getattr(idaapi, 'PR_BADSTACK', 0xb)) else '-' if idaapi.get_frame(ea) else '^'
            fgeneral = 'J' if func.flags & idaapi.FUNC_THUNK else 'L' if func.flags & idaapi.FUNC_LIB else 'S' if func.flags & idaapi.FUNC_STATICDEF else 'F'
            flags = itertools.chain(fgeneral, fframe, ftyped, ftagged)

            # naming information
            unmangled, realname = function.name(func), name(ea)

            # chunks and boundaries
            chunks = [item for item in function.chunks(func)]
            bounds = function.bounds(func)

            # try/except handlers
            if all(hasattr(idaapi, Fname) for Fname in ['tryblks_t', 'get_tryblks']):
                tb = idaapi.tryblks_t()
                blkcount = idaapi.get_tryblks(tb, func)
                trycount = sum(tb[i].is_cpp() for i in builtins.range(blkcount))
                iterable = (tb[i].cpp() if tb[i].is_cpp() else tb[i].seh() for i in builtins.range(tb.size()))
                ehcount = sum(item.size() for item in iterable)

            else:
                tb = None
                blkcount = trycount = ehcount = 0

            # now we can output everything that was found
            six.print_(u"{:<{:d}s} {:+#0{:d}x} : {:#0{:d}x}..{:#0{:d}x} : {:<{:d}s} {:s} : {:<{:d}s} : refs:{:<{:d}d} args:{:<{:d}d} lvars:{:<{:d}d} blocks:{:<{:d}d} exits:{:<{:d}d}{:s}".format(
                "[{:d}]".format(index), 2 + math.trunc(cindex),
                offset(ea), 3 + math.trunc(cmaxoffset),
                bounds[0], 2 + math.trunc(cminaddr), bounds[1], 2 + math.trunc(cmaxaddr),
                "({:d})".format(len(chunks)), 2 + cchunks, ''.join(flags),
                unmangled, math.trunc(maxname if internal.declaration.mangledQ(realname) else maxunmangled),
                len(xref.up(ea)), crefs,
                Fcount_avars(func), cavars,
                Fcount_lvars(func) if idaapi.get_frame(ea) else 0, clvars,
                len(builtins.list(function.blocks(func, silent=True))), cblocks,
                len(builtins.list(function.bottom(func))), cexits,
                " exceptions:{:d}+{:d}/{:d}".format(blkcount - trycount, trycount, ehcount) if tb else ''
            ))
        return

    @utils.multicase(string=six.string_types)
    @classmethod
    @utils.string.decorate_arguments('string')
    def search(cls, string):
        '''Search through all of the functions matching the glob `string` and return the first result.'''
        return cls.search(like=string)
    @utils.multicase()
    @classmethod
    @utils.string.decorate_arguments('name', 'like', 'regex')
    def search(cls, **type):
        '''Search through all of the functions within the database and return the first result matching the keyword specified by `type`.'''
        query_s = utils.string.kwargs(type)

        listable = [item for item in cls.iterate(**type)]
        if len(listable) > 1:
            messages = ((u"[{:d}] {:s}".format(i, function.name(ea))) for i, ea in enumerate(listable))
            [ logging.info(msg) for msg in messages ]
            f = utils.fcompose(function.by, function.name)
            logging.warning(u"{:s}.search({:s}) : Found {:d} matching results. Returning the first function \"{:s}\".".format('.'.join([__name__, cls.__name__]), query_s, len(listable), utils.string.escape(f(listable[0]), '"')))

        iterable = (item for item in listable)
        res = builtins.next(iterable, None)
        if res is None:
            raise E.SearchResultsError(u"{:s}.search({:s}) : Found 0 matching results.".format('.'.join([__name__, cls.__name__]), query_s))
        return res

class segments(object):
    r"""
    This namespace is used for listing all the segments inside the
    database. By default each segment's boundaries are yielded.

    The different types that one can match segments with are the following:

        `name` - Match according to the true segment name
        `like` - Filter the segment names according to a glob
        `regex` - Filter the segment names according to a regular-expression
        `index` - Match the segment by its index
        `identifier` - Match the segment by its identifier (``idaapi.segment_t.name``)
        `selector` - Match the segment by its selector (``idaapi.segment_t.sel``)
        `greater` or `gt` - Filter the segments for any after the specified address
        `less` or `lt` - Filter the segments for any before the specified address
        `predicate` - Filter the segments by passing its ``idaapi.segment_t`` to a callable

    Some examples of using these keywords are as follows::

        > for l, r in database.segments(): ...
        > database.segments.list(regex=r'\.r?data')
        > iterable = database.segments.iterate(like='*text*')
        > result = database.segments.search(greater=0x401000)

    """

    def __new__(cls):
        '''Yield the bounds of each segment within the current database.'''
        for seg in segment.__iterate__():
            yield interface.range.bounds(seg)
        return

    @utils.multicase(name=six.string_types)
    @classmethod
    @utils.string.decorate_arguments('name')
    def list(cls, name):
        '''List all of the segments defined in the database that match the glob `name`.'''
        return cls.list(like=name)
    @utils.multicase()
    @classmethod
    @utils.string.decorate_arguments('name', 'like', 'regex')
    def list(cls, **type):
        '''List all of the segments in the database that match the keyword specified by `type`.'''
        return segment.list(**type)

    @utils.multicase(name=six.string_types)
    @classmethod
    @utils.string.decorate_arguments('name')
    def iterate(cls, name):
        '''Iterate through all of the segments in the database with a glob that matches `name`.'''
        return cls.iterate(like=name)
    @utils.multicase()
    @classmethod
    @utils.string.decorate_arguments('name', 'like', 'regex')
    def iterate(cls, **type):
        '''Iterate through all the segments defined in the database matching the keyword specified by `type`.'''
        return segment.__iterate__(**type)

    @utils.multicase(name=six.string_types)
    @classmethod
    @utils.string.decorate_arguments('name')
    def search(cls, name):
        '''Search through all of the segments matching the glob `name` and return the first result.'''
        return cls.search(like=name)
    @utils.multicase()
    @classmethod
    @utils.string.decorate_arguments('name', 'like', 'regex')
    def search(cls, **type):
        '''Search through all of the segments within the database and return the first result matching the keyword specified by `type`.'''
        return segment.search(**type)

@utils.multicase()
def instruction():
    '''Return the instruction at the current address as a string.'''
    return instruction(ui.current.address())
@utils.multicase(ea=six.integer_types)
def instruction(ea):
    '''Return the instruction at the address `ea` as a string.'''
    ash = idaapi.cvar.ash if idaapi.__version__ < 7.5 else idaapi.get_ash()
    cmnt1, cmnt2 = ash.cmnt, ash.cmnt2

    # first grab the disassembly and then remove all of IDA's tag information from it
    insn = idaapi.generate_disasm_line(interface.address.inside(ea))
    unformatted = idaapi.tag_remove(insn)

    # if there's a terminating comment character, locate it, and then slice out just the comment
    if cmnt2:
        lindex = unformatted.rfind(cmnt1)
        rindex = lindex + unformatted[lindex:].find(cmnt2) + len(cmnt2)
        nocomment = unformatted if lindex < 0 else unformatted[:lindex] if rindex < 0 else (nocomment[:lindex] + nocomment[rindex:])

    # there's no terminating comment character, so we just need to cull out everything after cmnt1
    elif cmnt1:
        index = unformatted.rfind(cmnt1)
        nocomment = unformatted if index < 0 else unformatted[:index]

    # if the starting cmnt1 character isn't defined, then we don't do anything.
    else:
        nocomment = unformatted

    # combine any multiple spaces into just a single space and return it
    res = utils.string.of(nocomment.strip())
    return functools.reduce(lambda agg, char: agg + (('' if agg.endswith(' ') else ' ') if char == ' ' else char), res, '')

@utils.multicase()
def disassemble(**options):
    '''Disassemble the instructions at the current address.'''
    return disassemble(ui.current.address(), **options)
@utils.multicase(ea=six.integer_types)
def disassemble(ea, **options):
    """Disassemble the instructions at the address specified by `ea`.

    If the integer `count` is specified, then return `count` number of instructions.
    If the bool `comments` is true, then return the comments for each instruction as well.
    """
    ea = interface.address.inside(ea)
    commentQ = builtins.next((options[k] for k in ['comment', 'comments'] if k in options), False)

    # grab the values we need in order to distinguish a comment
    ash = idaapi.cvar.ash if idaapi.__version__ < 7.5 else idaapi.get_ash()
    cmnt1, cmnt2 = ash.cmnt, ash.cmnt2

    # enter a loop that goes through the number of line items requested by the user
    res, count = [], options.get('count', 1)
    while count > 0:
        # grab the instruction and remove all of IDA's tag information from it
        insn = idaapi.generate_disasm_line(ea) or ''
        unformatted = idaapi.tag_remove(insn)

        # check if the terminating char (cmnt2) is defined
        if cmnt2:
            lindex = unformatted.rfind(cmnt1)
            rindex = lindex + unformatted[lindex:].find(cmnt2) + len(cmnt2)

            # so that we can separate the comment out of it
            nocomment = unformatted if lindex < 0 else unformatted[:lindex] if rindex < 0 else (nocomment[:lindex] + nocomment[rindex:])
            comment = unformatted[lindex : lindex] if lindex < 0 else unformatted[lindex:] if rindex < 0 else comment[lindex : rindex]

        # if it's not, then just use the starting char (cmnt1) to find the comment
        elif cmnt1:
            index = unformatted.rfind(cmnt1)
            nocomment, comment = (unformatted, unformatted[index : index]) if index < 0 else (unformatted[:index], unformatted[index:])

        # if this comment is undefined, then there ain't shit we can do with it,
        # and we need to just append it as-is
        else:
            res.append(u"{:x}: {:s}".format(ea, unformatted.strip()))

        # remove any surrounding spaces from the instruction
        stripped = nocomment.strip()

        # combine all multiple spaces together so it's single-spaced
        noextraspaces = functools.reduce(lambda agg, char: agg + (('' if agg.endswith(' ') else ' ') if char == ' ' else char), utils.string.of(stripped), '')

        # if we've been asked to include the comment, then first we need to clean
        # it up a bit.
        if commentQ:
            cleaned = comment[len(cmnt1) : -len(cmnt2)] if cmnt2 else comment[len(cmnt1):]
            stripped = cleaned.strip()

            # then we can concatenate it with our instruction and its comment characters
            withcharacters = u''.join([u"{:s} ".format(cmnt1) if cmnt1 else u'', stripped, u" {:s}".format(cmnt2) if cmnt2 else u''])

            # and then we can append it to our result
            res.append(u"{:x}: {:s}{:s}".format(ea, noextraspaces, u" {:s}".format(withcharacters) if stripped else ''))

        # otherwise we cna simply append it to our result with the address in front
        else:
            res.append(u"{:x}: {:s}".format(ea, noextraspaces))

        # move on to the next iteration
        ea = address.next(ea) if count > 1 else address.tail(ea)
        count -= 1
    return '\n'.join(res)
disasm = utils.alias(disassemble)

@utils.multicase()
def read():
    '''Return the bytes defined at the current address.'''
    res = ui.current.address()
    return read(res, type.size(res))
@utils.multicase(ea=six.integer_types)
def read(ea):
    '''Return the number of bytes associated with the address `ea`.'''
    return read(ea, type.size(ea))
@utils.multicase(ea=six.integer_types, size=six.integer_types)
def read(ea, size):
    '''Return `size` number of bytes from address `ea`.'''
    get_bytes = idaapi.get_many_bytes if idaapi.__version__ < 7.0 else idaapi.get_bytes
    start, end = interface.address.within(ea, ea + size)
    return get_bytes(ea, end - start) or b''
@utils.multicase(bounds=tuple)
def read(bounds):
    '''Return the bytes within the specified `bounds`.'''
    get_bytes = idaapi.get_many_bytes if idaapi.__version__ < 7.0 else idaapi.get_bytes
    bounds = ea, _ = interface.bounds_t(*bounds)
    return get_bytes(ea, bounds.size) or b''

@utils.multicase(data=bytes)
def write(data, **persist):
    '''Modify the database at the current address with the bytes specified in `data`.'''
    return write(ui.current.address(), data, **persist)
@utils.multicase(ea=six.integer_types, data=bytes)
def write(ea, data, **persist):
    """Modify the database at address `ea` with the bytes specified in `data`

    If the bool `persist` is specified, then modify what IDA considers the original bytes.
    """
    patch_bytes, put_bytes = (idaapi.patch_many_bytes, idaapi.put_many_bytes) if idaapi.__version__ < 7.0 else (idaapi.patch_bytes, idaapi.put_bytes)

    ea, _ = interface.address.within(ea, ea + len(data))
    originalQ = builtins.next((persist[k] for k in ['original', 'persist', 'store', 'save'] if k in persist), False)
    return patch_bytes(ea, data) if originalQ else put_bytes(ea, data)

class names(object):
    """
    This namespace is used for listing all of the names (symbols) within the
    database. By default the `(address, name)` is yielded in its mangled form.

    When listing names that are matched, the following legend can be used to
    identify certain characteristics about the address of the returned name:

        `I` - The symbol is residing in an import segment
        `C` - The address of the symbol is marked as code
        `D` - The address of the symbol is marked as data
        `^` - The address of the symbol is is initialized
        `+` - The symbol has an implicit tag applied to it (named or typed)
        `*` - The symbol has an explicit tag applied to it

    The available types that one can filter the symbols with are as follows:

        `address` - Match according to the address of the symbol
        `name` - Match according to the name of the unmangled symbol
        `unmangled` - Filter the unmangled symbol names according to a regular-expression
        `like` - Filter the symbol names according to a glob
        `regex` - Filter the symbol names according to a regular-expression
        `index` - Match the symbol according to its index
        `function` - Filter the symbol names for any that are referring to a function
        `imports` - Filter the symbol names for any that are imports
        `typed` - Filter the symbol names for any that have type information applied to them
        `tagged` - Filter the symbol names for any that use the specified tag(s)
        `predicate` - Filter the symbols by passing their address to a callable

    Some examples of using these keywords are as follows::

        > list(database.names())
        > database.names.list(index=31)
        > iterable = database.names.iterate(like='str.*')
        > result = database.names.search(name='some_really_sick_symbol_name')

    """
    __matcher__ = utils.matcher()
    __matcher__.mapping('address', idaapi.get_nlist_ea), __matcher__.mapping('ea', idaapi.get_nlist_ea)
    __matcher__.boolean('name', lambda name, item: name.lower() == item.lower(), idaapi.get_nlist_name, internal.declaration.demangle)
    __matcher__.combinator('like', utils.fcompose(fnmatch.translate, utils.fpartial(re.compile, flags=re.IGNORECASE), operator.attrgetter('match')), idaapi.get_nlist_name, utils.string.of)
    __matcher__.combinator('regex', utils.fcompose(utils.fpartial(re.compile, flags=re.IGNORECASE), operator.attrgetter('match')), idaapi.get_nlist_name, utils.string.of)
    __matcher__.combinator('unmangled', utils.fcompose(utils.fpartial(re.compile, flags=re.IGNORECASE), operator.attrgetter('match')), idaapi.get_nlist_name, internal.declaration.demangle)
    __matcher__.combinator('demangled', utils.fcompose(utils.fpartial(re.compile, flags=re.IGNORECASE), operator.attrgetter('match')), idaapi.get_nlist_name, internal.declaration.demangle)
    __matcher__.mapping('function', function.within, idaapi.get_nlist_ea)
    __matcher__.mapping('imports', utils.fpartial(operator.eq, idaapi.SEG_XTRN), idaapi.get_nlist_ea, idaapi.segtype)
    __matcher__.boolean('tagged', lambda parameter, keys: operator.truth(keys) == parameter if isinstance(parameter, bool) else operator.contains(keys, parameter) if isinstance(parameter, six.string_types) else keys&parameter, idaapi.get_nlist_ea, lambda ea: function.tag(ea) if function.within(ea) else tag(ea), operator.methodcaller('keys'), builtins.set)
    __matcher__.mapping('typed', operator.truth, idaapi.get_nlist_ea, lambda ea: idaapi.get_tinfo2(ea, idaapi.tinfo_t()) if idaapi.__version__ < 7.0 else idaapi.get_tinfo(idaapi.tinfo_t(), ea))
    __matcher__.predicate('predicate', idaapi.get_nlist_ea)
    __matcher__.predicate('pred', idaapi.get_nlist_ea)
    __matcher__.attribute('index')

    def __new__(cls):
        '''Iterate through all of the names in the database yielding a tuple of the address and its name.'''
        for index in builtins.range(idaapi.get_nlist_size()):
            res = zip([idaapi.get_nlist_ea, utils.fcompose(idaapi.get_nlist_name, utils.string.of)], 2 * [index])
            yield tuple(f(x) for f, x in res)
        return

    @utils.multicase(string=six.string_types)
    @classmethod
    @utils.string.decorate_arguments('string')
    def __iterate__(cls, string):
        return cls.__iterate__(like=string)
    @utils.multicase()
    @classmethod
    @utils.string.decorate_arguments('name', 'like', 'regex')
    def __iterate__(cls, **type):
        iterable = (idx for idx in builtins.range(idaapi.get_nlist_size()))
        for key, value in (type or {'predicate': utils.fconstant(True)}).items():
            iterable = cls.__matcher__.match(key, value, iterable)
        for item in iterable: yield item

    @utils.multicase(string=six.string_types)
    @classmethod
    @utils.string.decorate_arguments('string')
    def iterate(cls, string):
        '''Iterate through all of the names in the database with a glob that matches `string`.'''
        return cls.iterate(like=string)
    @utils.multicase()
    @classmethod
    @utils.string.decorate_arguments('name', 'like', 'regex')
    def iterate(cls, **type):
        '''Iterate through all of the names in the database that match the keyword specified by `type`.'''
        for idx in cls.__iterate__(**type):
            ea, name = idaapi.get_nlist_ea(idx), idaapi.get_nlist_name(idx)
            yield ea, utils.string.of(name)
        return

    @utils.multicase(string=six.string_types)
    @classmethod
    @utils.string.decorate_arguments('string')
    def list(cls, string):
        '''List all of the names in the database with a glob that matches `string`.'''
        return cls.list(like=string)
    @utils.multicase()
    @classmethod
    @utils.string.decorate_arguments('name', 'like', 'regex')
    def list(cls, **type):
        '''List all of the names in the database that match the keyword specified by `type`.'''
        MANGLED_CODE, MANGLED_DATA, MANGLED_UNKNOWN = getattr(idaapi, 'MANGLED_CODE', 0), getattr(idaapi, 'MANGLED_DATA', 1), getattr(idaapi, 'MANGLED_UNKNOWN', 2)
        Fmangled_type = idaapi.get_mangled_name_type if hasattr(idaapi, 'get_mangled_name_type') else utils.fcompose(utils.frpartial(idaapi.demangle_name, 0), utils.fcondition(operator.truth)(MANGLED_DATA, MANGLED_UNKNOWN))
        MNG_NODEFINIT, MNG_NOPTRTYP, MNG_LONG_FORM = getattr(idaapi, 'MNG_NODEFINIT', 8), getattr(idaapi, 'MNG_NOPTRTYP', 7), getattr(idaapi, 'MNG_LONG_FORM', 0x6400007)

        # Set some reasonable defaults
        maxindex = 1
        maxaddr = maxname = 0

        # Perform the first pass through our listable grabbing our field lengths
        listable = []
        for index in cls.__iterate__(**type):
            maxindex = max(index, maxindex)
            maxaddr = max(idaapi.get_nlist_ea(index), maxaddr)
            maxname = max(len(idaapi.get_nlist_name(index)), maxname)

            listable.append(index)

        # Collect the sizes from our first pass
        cindex, caddr = utils.string.digits(maxindex, 10), utils.string.digits(maxaddr, 16)

        # List all the fields of each name that was found
        for index in listable:
            ea, name = ui.navigation.set(idaapi.get_nlist_ea(index)), utils.string.of(idaapi.get_nlist_name(index))
            tags = function.tag(ea) if function.within(ea) else tag(ea)

            # Any flags that could be useful
            ftype = 'I' if idaapi.segtype(ea) == idaapi.SEG_XTRN else '-' if t.is_unknown(ea) else 'C' if t.is_code(ea) else 'D' if t.is_data(ea) else '-'
            finitialized = '^' if t.is_initialized(ea) else '-'
            tags.pop('__name__', None)
            ftagged = '-' if not tags else '*' if any(not item.startswith('__') for item in tags) else '+'
            flags = itertools.chain(finitialized, ftype, ftagged)

            # Figure out which name we need to use, the mangled one or the real one.
            mangled_name_type_t = Fmangled_type(utils.string.to(name))
            realname = name if mangled_name_type_t == MANGLED_UNKNOWN else (idaapi.demangle_name(utils.string.to(name), MNG_NODEFINIT|MNG_NOPTRTYP) or name)

            # Now we can just try to demangle the name and display both mangled and unmangled forms.
            description = utils.string.of(idaapi.demangle_name(utils.string.to(name), MNG_LONG_FORM) or realname)
            six.print_(u"{:<{:d}s} {:#0{:d}x} : {:s} : {:>{:d}s} : {:s}".format("[{:d}]".format(index), 2 + math.trunc(cindex), ea, math.trunc(caddr), ''.join(flags), '' if realname == name else "({:s})".format(name), 2 + maxname, description))
        return

    @utils.multicase(string=six.string_types)
    @classmethod
    @utils.string.decorate_arguments('string')
    def search(cls, string):
        '''Search through all of the names matching the glob `string` and return the first result.'''
        return cls.search(like=string)
    @utils.multicase()
    @classmethod
    @utils.string.decorate_arguments('name', 'like', 'regex')
    def search(cls, **type):
        '''Search through all of the names within the database and return the first result matching the keyword specified by `type`.'''
        MANGLED_CODE, MANGLED_DATA, MANGLED_UNKNOWN = getattr(idaapi, 'MANGLED_CODE', 0), getattr(idaapi, 'MANGLED_DATA', 1), getattr(idaapi, 'MANGLED_UNKNOWN', 2)
        Fmangled_type = idaapi.get_mangled_name_type if hasattr(idaapi, 'get_mangled_name_type') else utils.fcompose(utils.frpartial(idaapi.demangle_name, 0), utils.fcondition(operator.truth)(MANGLED_CODE if type.is_code(ea) else MANGLED_DATA, MANGLED_UNKNOWN))
        MNG_LONG_FORM = getattr(idaapi, 'MNG_LONG_FORM', 0x6400007)

        query_s = utils.string.kwargs(type)
        listable = [item for item in cls.__iterate__(**type)]
        if len(listable) > 1:
            f1, f2 = idaapi.get_nlist_ea, utils.fcompose(idaapi.get_nlist_name, utils.string.of)
            messages = ((u"[{:d}] {:#x} {:s}".format(idx, ea, name if Fmangled_type(utils.string.to(name)) == MANGLED_UNKNOWN else "({:s}) {:s}".format(name, utils.string.of(idaapi.demangle_name(name, MNG_LONG_FORM) or name))) for idx, ea, name in map(utils.fmap(utils.fidentity, f1, f2), listable)))
            [ logging.info(msg) for msg in messages ]
            logging.warning(u"{:s}.search({:s}) : Found {:d} matching results, Returning the first item at {:#x} with the name \"{:s}\".".format('.'.join([__name__, cls.__name__]), query_s, len(listable), f1(listable[0]), utils.string.escape(f2(listable[0]), '"')))

        iterable = (item for item in listable)
        res = builtins.next(iterable, None)
        if res is None:
            raise E.SearchResultsError(u"{:s}.search({:s}) : Found 0 matching results.".format('.'.join([__name__, cls.__name__]), query_s))
        return idaapi.get_nlist_ea(res)

    @utils.multicase()
    @classmethod
    def symbol(cls):
        '''Return the symbol name of the current address.'''
        return cls.symbol(ui.current.address())
    @utils.multicase(ea=six.integer_types)
    @classmethod
    def symbol(cls, ea):
        '''Return the symbol name of the address `ea`.'''
        res = idaapi.get_nlist_idx(ea)
        return utils.string.of(idaapi.get_nlist_name(res))
    name = utils.alias(symbol, 'names')

    @classmethod
    def address(cls, index):
        '''Return the address of the symbol at `index`.'''
        return idaapi.get_nlist_ea(index)

    @utils.multicase()
    @classmethod
    def at(cls):
        '''Return the index, symbol address, and name at the current address.'''
        return cls.at(ui.current.address())
    @utils.multicase(ea=six.integer_types)
    @classmethod
    def at(cls, ea):
        '''Return the index, symbol address, and name at the address `ea`.'''
        idx = idaapi.get_nlist_idx(ea)
        ea, name = idaapi.get_nlist_ea(idx), idaapi.get_nlist_name(idx)
        return idx, ea, utils.string.of(name)

class search(object):
    """
    This namespace used for searching the database using IDA's find
    functionality.

    By default the name is used, however there are 4 search methods
    that are available. The methods that are provided are:

        ``search.by_bytes`` - Search by the specified hex bytes
        ``search.by_regex`` - Search by the specified regex
        ``search.by_text``  - Search by the specified text
        ``search.by_name``  - Search by the specified name

    Each search method has its own options, but all of them take an extra
    boolean option, `reverse`, which specifies whether to search backwards
    from the starting position or forwards.

    The ``search.iterate`` function allows one to iterate through all the results
    discovered in the database. One variation of ``search.iterate`` takes a 3rd
    parameter `predicate`. This allows usage of one of the search methods provided
    or to allow a user to include their own. This function will then yield each
    matched search result.
    """

    @utils.multicase()
    @classmethod
    def by_bytes(cls, data, **direction):
        '''Search through the database at the current address for the bytes specified by `data`.'''
        return cls.by_bytes(ui.current.address(), data, **direction)
    @utils.multicase(ea=six.integer_types)
    @classmethod
    def by_bytes(cls, ea, data, **direction):
        """Search through the database at address `ea` for the bytes specified by `data`.

        If `reverse` is specified as a bool, then search backwards from the given address.
        If `radix` is specified, then use it as the numerical radix for describing the bytes.
        If `radix` is not specified, then assume that `data` represents the exact bytes to search.
        """
        radix = direction.get('radix', 0)
        left, right = config.bounds()

        # Figure out the correct format depending on the radix that we were given by the caller.
        formats = {8: "{:0o}".format, 10: "{:d}".format, 16: "{:02X}".format}
        if radix and not operator.contains(formats, radix):
            raise E.InvalidParameterError(u"{:s}.by_bytes({:#x}, {:s}{:s}) : In invalid radix ({:d}) was specified.".format('.'.join([__name__, search.__name__]), ea, '...' if isinstance(data, idaapi.compiled_binpat_vec_t) else utils.string.repr(data), u", {:s}".format(utils.string.kwargs(direction)) if direction else '', radix))
        format = formats[radix or 16]

        # If we're using an earlier version of IDA, then we need to completely build the query ourselves.
        if idaapi.__version__ < 7.5:

            # Convert the bytes directly into a string of base-10 integers.
            if (isinstance(data, bytes) and radix == 0) or isinstance(data, bytearray):
                query = ' '.join(map(format, bytearray(data)))

            # Convert the string directly into a string of base-10 integers.
            elif isinstance(data, six.string_types) and radix == 0:
                query = ' '.join(map(format, itertools.chain(*(((ord(ch) & 0xff00) // 0x100, (ord(ch) & 0x00ff) // 0x1) for ch in data))))

            # Otherwise, leave it alone because the user specified the radix already.
            else:
                query = data

            # Assign our flags according to whatever the direction the user gave us.
            reversed = builtins.next((direction[k] for k in ['reverse', 'reversed', 'up', 'backwards'] if k in direction), False)
            flags = idaapi.SEARCH_UP if reversed else idaapi.SEARCH_DOWN

            # Now we can start our actual searching for things.
            start, stop = (left, ea) if reversed else (ea, right)
            res = idaapi.find_binary(start, stop, utils.string.to(query), radix or 16, idaapi.SEARCH_CASE | flags)
            if res == idaapi.BADADDR:
                raise E.SearchResultsError(u"{:s}.by_bytes({:#x}, {:s}{:s}) : The specified bytes ({!s}) were not found.".format('.'.join([__name__, cls.__name__]), ea, utils.string.repr(data), u", {:s}".format(utils.string.kwargs(direction)) if direction else '', query))
            return res

        # Now that we know the radix, if we were given bytes then we need to format them into the right query.
        if isinstance(data, (bytes, bytearray)):
            query = ' '.join(map(format, bytearray(data)))

        # If we were given a string, then we need to encode it into some bytes.
        elif isinstance(data, six.string_types):
            query = ' '.join(map(format, itertools.chain(*(((ord(ch) & 0xff00) // 0x100, (ord(ch) & 0x00ff) // 0x1) for ch in data))))

        # If we were given an idaapi.compiled_binpat_vec_t already, then the user knows what they're doing.
        elif isinstance(data, idaapi.compiled_binpat_vec_t):
            query = data

        else:
            raise E.InvalidParameterError(u"{:s}.by_bytes({:#x}, {:s}{:s}) : A query of an unsupported type ({!s}) was provided.".format('.'.join([__name__, search.__name__]), ea, '...' if isinstance(data, idaapi.compiled_binpat_vec_t) else utils.string.repr(data), u", {:s}".format(utils.string.kwargs(direction)) if direction else '', string.__class__))

        # Now we can actually parse what we were given if we weren't already given a pattern.
        if not isinstance(query, idaapi.compiled_binpat_vec_t):
            patterns = idaapi.compiled_binpat_vec_t()

            # It seems that idaapi.parse_binpat_str() returns an empty string on success, and None on failure...
            res = idaapi.parse_binpat_str(patterns, ea, utils.string.to(query), radix, direction.get('encoding', 0))
            ok = not (res is None)

        # Otherwise we were given an idaapi.compiled_binpat_vec_t, and we don't need to do any parsing.
        else:
            ok, patterns = len(query) > 0, query

        # If parsing has failed in some way, then throw up an error for the user to act upon.
        if not ok:
            queries = (' '.join(map(format, bytearray(item.bytes))) for item in patterns) if len(patterns) else [query]
            raise E.InvalidParameterError(u"{:s}.by_bytes({:#x}, {:s}{:s}) : Unable to parse the specified quer{:s} ({:s}).".format('.'.join([__name__, search.__name__]), ea, '...' if isinstance(data, idaapi.compiled_binpat_vec_t) else utils.string.repr(data), u", {:s}".format(utils.string.kwargs(direction)) if direction else '', 'ies' if len(patterns) > 1 else 'y', ', '.join("\"{:s}\"".format(utils.string.escape(item, '"')) for item in queries)))

        # Once we have our pattern, let's figure first figure out our direction flags.
        reversed = builtins.next((direction[k] for k in ['reverse', 'reversed', 'up', 'backwards'] if k in direction), False)

        # Then we figure out what case option the user gave us if there was one.
        if any(k in direction for k in ['case', 'sensitive', 'casesensitive']):
            foldcase = not builtins.next(direction[k] for k in ['case', 'sensitive', 'casesensitive'])

        elif any(k in direction for k in ['fold', 'folded', 'foldcase', 'insensitive', 'nocase', 'caseless', 'caseinsensitive']):
            foldcase = builtins.next(direction[k] for k in ['fold', 'folded', 'foldcase', 'insensitive', 'nocase', 'caseless', 'caseinsensitive'])

        # Otherwise we'll be doing a case-insensitive search (non-folded case).
        else:
            foldcase = False

        # Finally we can update the flags with whatever the user gave us.
        flags = direction.get('flags', 0)
        flags |= idaapi.BIN_SEARCH_BACKWARD if reversed else idaapi.BIN_SEARCH_FORWARD
        flags |= idaapi.BIN_SEARCH_NOCASE if foldcase else idaapi.BIN_SEARCH_CASE

        # Now we actually perform our idaapi.bin_search().
        result = idaapi.bin_search(left, ea, patterns, flags) if reversed else idaapi.bin_search(ea, right, patterns, flags)
        if result == idaapi.BADADDR:
            queries = (' '.join(map(format, bytearray(item.bytes))) for item in patterns)
            raise E.SearchResultsError(u"{:s}.by_bytes({:#x}, {:s}{:s}) : The specified bytes described by the quer{:s} ({:s}) were not found.".format('.'.join([__name__, search.__name__]), ea, '...' if isinstance(data, idaapi.compiled_binpat_vec_t) else utils.string.repr(data), u", {:s}".format(utils.string.kwargs(direction)) if direction else '', 'ies' if len(patterns) > 1 else 'y', ', '.join("\"{:s}\"".format(utils.string.escape(item, '"')) for item in queries)))
        return result

    bybytes = utils.alias(by_bytes, 'search')

    @utils.multicase(string=six.string_types)
    @classmethod
    @utils.string.decorate_arguments('string')
    def by_regex(string, **options):
        '''Search through the database at the current address for the regex matched by `string`.'''
        return cls.by_regex(ui.current.address(), string, **options)
    @utils.multicase(ea=six.integer_types, string=six.string_types)
    @classmethod
    @utils.string.decorate_arguments('string')
    def by_regex(cls, ea, string, **options):
        """Search the database at address `ea` for the regex matched by `string`.

        If `reverse` is specified as a bool, then search backwards from the given address.
        If `sensitive` is specified as bool, then perform a case-sensitive search.
        """
        queryF = utils.string.to

        reversed = builtins.next((options[k] for k in ['reverse', 'reversed', 'up', 'backwards'] if k in options), False)
        flags = idaapi.SEARCH_REGEX
        flags |= idaapi.SEARCH_UP if reversed else idaapi.SEARCH_DOWN
        flags |= idaapi.SEARCH_CASE if options.get('sensitive', False) else 0
        res = idaapi.find_text(ea, 0, 0, queryF(string), flags)
        if res == idaapi.BADADDR:
            raise E.SearchResultsError(u"{:s}.by_regex({:#x}, \"{:s}\"{:s}) : The specified regex was not found.".format('.'.join([__name__, cls.__name__]), ea, utils.string.escape(string, '"'), u", {:s}".format(utils.string.kwargs(options)) if options else '', res))
        return res
    byregex = utils.alias(by_regex, 'search')

    @utils.multicase(string=six.string_types)
    @classmethod
    @utils.string.decorate_arguments('string')
    def by_text(string, **options):
        '''Search through the database at the current address for the text matched by `string`.'''
        return cls.by_text(ui.current.address(), string, **options)
    @utils.multicase(ea=six.integer_types, string=six.string_types)
    @classmethod
    @utils.string.decorate_arguments('string')
    def by_text(cls, ea, string, **options):
        """Search the database at address `ea` for the text matched by `string`.

        If `reverse` is specified as a bool, then search backwards from the given address.
        If `sensitive` is specified as bool, then perform a case-sensitive search.
        """
        queryF = utils.string.to

        reversed = builtins.next((options[k] for k in ['reverse', 'reversed', 'up', 'backwards'] if k in options), False)
        flags = 0
        flags |= idaapi.SEARCH_UP if reversed else idaapi.SEARCH_DOWN
        flags |= idaapi.SEARCH_CASE if options.get('sensitive', False) else 0
        res = idaapi.find_text(ea, 0, 0, queryF(string), flags)
        if res == idaapi.BADADDR:
            raise E.SearchResultsError(u"{:s}.by_text({:#x}, \"{:s}\"{:s}) : The specified text was not found.".format('.'.join([__name__, cls.__name__]), ea, utils.string.escape(string, '"'), u", {:s}".format(utils.string.kwargs(options)) if options else '', res))
        return res
    bytext = by_string = bystring = utils.alias(by_text, 'search')

    @utils.multicase(name=six.string_types)
    @classmethod
    @utils.string.decorate_arguments('name')
    def by_name(name, **options):
        '''Search through the database at the current address for the symbol `name`.'''
        return cls.by_name(ui.current.address(), name, **options)
    @utils.multicase(ea=six.integer_types, name=six.string_types)
    @classmethod
    @utils.string.decorate_arguments('name')
    def by_name(ea, name, **options):
        """Search through the database at address `ea` for the symbol `name`.

        If `reverse` is specified as a bool, then search backwards from the given address.
        If `sensitive` is specified as bool, then perform a case-sensitive search.
        """
        queryF = utils.string.to

        reversed = builtins.next((options[k] for k in ['reverse', 'reversed', 'up', 'backwards'] if k in options), False)
        flags = idaapi.SEARCH_IDENT
        flags |= idaapi.SEARCH_UP if reversed else idaapi.SEARCH_DOWN
        flags |= idaapi.SEARCH_CASE if options.get('sensitive', False) else 0
        res = idaapi.find_text(ea, 0, 0, queryF(name), flags)
        if res == idaapi.BADADDR:
            raise E.SearchResultsError(u"{:s}.by_name({:#x}, \"{:s}\"{:s}) : The specified name was not found.".format('.'.join([__name__, cls.__name__]), ea, utils.string.escape(name, '"'), u", {:s}".format(utils.string.kwargs(options)) if options else '', res))
        return res
    byname = utils.alias(by_name, 'search')

    @utils.multicase(pattern=(six.string_types, bytes, bytearray))
    @classmethod
    def iterate(cls, pattern, **options):
        '''Iterate through all search results that match the `pattern` starting at the current address.'''
        predicate = options.pop('predicate', cls)
        return cls.iterate(ui.current.address(), pattern, predicate, **options)
    @utils.multicase(ea=six.integer_types, pattern=(six.string_types, bytes, bytearray))
    @classmethod
    def iterate(cls, ea, pattern, **options):
        '''Iterate through all search results that match the specified `pattern` starting at address `ea`.'''
        predicate = options.pop('predicate', cls)
        return cls.iterate(ea, pattern, predicate, **options)
    @utils.multicase(pattern=(six.string_types, bytes, bytearray))
    @classmethod
    def iterate(cls, pattern, predicate, **options):
        '''Iterate through all search results matched by the function `predicate` with the specified `pattern` starting at the current address.'''
        return cls.iterate(ui.current.address(), pattern, predicate, **options)
    @utils.multicase(ea=six.integer_types, pattern=(six.string_types, bytes, bytearray))
    @classmethod
    def iterate(cls, ea, pattern, predicate, **options):
        '''Iterate through all search results matched by the function `predicate` with the specified `pattern` starting at address `ea`.'''
        reversed = builtins.next((options[k] for k in ['reverse', 'reversed', 'up', 'backwards'] if k in options), False)
        Fnext = address.prev if reversed else address.next

        # If our predicate is a string, then we need to ensure that it's one that
        # we know about. We cheat here by checking it against our current namespace.
        if isinstance(predicate, six.string_types) and not hasattr(cls, predicate):
            raise E.InvalidParameterError(u"{:s}.iterate({:#x}, {:s}, {:s}, {:s}) : The provided predicate ({:s}) is unknown and does not refer to anything within the \"{:s}\" namespace.".format('.'.join([__name__, cls.__name__]), ea, utils.string.repr(pattern), utils.string.repr(predicate), u", {:s}".format(utils.string.kwargs(options)) if options else '', predicate, cls.__name__))

        # Now we either grab the predicate from the namespace or use it as-is.
        predicate = getattr(cls, predicate) if isinstance(predicate, six.string_types) else predicate

        # Now we can begin our traversal of all search results using it.
        try:
            ea = predicate(ea, pattern, **options)
            while ea != idaapi.BADADDR:
                yield ea
                ea = predicate(Fnext(ea), pattern, **options)
        except E.SearchResultsError:
            return
        return

    @utils.multicase()
    def __new__(cls, pattern, **direction):
        '''Search through the database at the current address for the specified `pattern`.'''
        return cls(ui.current.address(), pattern, **direction)
    @utils.multicase(ea=six.integer_types)
    def __new__(cls, ea, pattern, **direction):
        """Search through the database at address `ea` for the specified `pattern`.'''

        If `reverse` is specified as a bool, then search backwards from the given address.
        If `radix` is specified, then use it as the numerical radix for describing the bytes.
        If `radix` is not specified, then assume that `data` represents the exact bytes to search.
        """
        if idaapi.__version__ < 7.5:
            direction.setdefault('radix', 16)
            return cls.by_bytes(ea, pattern, **direction)

        # If we're using a more recent version of IDA, then we can actually allow users to
        # specify their own full queries here. If they already gave us an idaapi.compiled_binpat_vec_t,
        # then we just pass that through onto by_bytes.
        if isinstance(pattern, idaapi.compiled_binpat_vec_t):
            return cls.by_bytes(ea, pattern, **direction)

        # Check if we were given multiple patterns for any particular reason and
        # combine them into a list so we can parse them all individually.
        listable = pattern if isinstance(pattern, (builtins.tuple, builtins.set, builtins.list)) else [pattern]
        patterns = [pattern for pattern in listable]

        # Extract the radix if we were given one so that we can pretty up the logs.
        radix, formats = direction.get('radix', 16), {8: "{:0o}".format, 10: "{:d}".format, 16: "{:02x}".format}
        if not operator.contains(formats, radix):
            raise E.InvalidParameterError(u"{:s}({:#x}, {:s}{:s}) : In invalid radix ({:d}) was specified.".format('.'.join([__name__, cls.__name__]), ea, utils.string.repr(patterns), u", {:s}".format(utils.string.kwargs(direction)) if direction else '', radix))
        format = formats[radix]

        # Now we need to parse them all individually into an idaapi.compiled_binpat_vec_t().
        result = idaapi.compiled_binpat_vec_t()
        for index, item in enumerate(patterns):

            # If we were given some bytes instead of a string, then format them into a
            # proper string using the specified radix.
            string = ' '.join(map(format, bytearray(item))) if isinstance(item, (bytes, bytearray)) else item

            # Now to parse each one with idaapi.parse_binpat_str(), but of course the idaapi.parse_binpat_str()
            # api returns an empty string on success and a None on failure.
            if idaapi.parse_binpat_str(result, ea, utils.string.to(string), radix, direction.get('encoding', idaapi.PBSENC_ALL)) is None:
                raise E.DisassemblerError(u"{:s}({:#x}, {:s}{:s}) : Unable to parse the provided pattern {:s}(\"{:s}\").".format('.'.join([__name__, cls.__name__]), ea, utils.string.repr(patterns), u", {:s}".format(utils.string.kwargs(direction)) if direction else '', "at index {:d} ".format(index) if len(patterns) > 1 else '', utils.string.escape(string, '"')))

            # Log what was just parsed to help with debugging things.
            parsed = result[index]
            description = "{:s}" if parsed.all_bytes_defined() else "{:s}) with mask ({:s}"
            logging.info(u"{:s}({:#x}, {:s}{:s}) : Successfully parsed the pattern at index {:d} (\"{:s}\") into bytes ({:s}).".format('.'.join([__name__, cls.__name__]), ea, utils.string.repr(patterns), u", {:s}".format(utils.string.kwargs(direction)) if direction else '', index, utils.string.escape(string, '"'), description.format(*(' '.join(map(format, bytearray(item))) for item in [parsed.bytes, parsed.mask]))))

        # Everything was parsed, so we should be able to just hand things off to by_bytes.
        return cls.by_bytes(ea, result, **direction)

byname = by_name = utils.alias(search.by_name, 'search')

def go(ea):
    '''Jump to the specified address at `ea`.'''
    if isinstance(ea, six.string_types):
        ea = search.by_name(None, ea)
    idaapi.jumpto(interface.address.inside(ea))
    return ea

def go_offset(offset):
    '''Jump to the specified `offset` within the database.'''
    res, ea = address.offset(ui.current.address()), address.by_offset(offset)
    idaapi.jumpto(interface.address.inside(ea))
    return res
goof = gooffset = gotooffset = goto_offset = utils.alias(go_offset)

@utils.multicase()
def name(**flags):
    '''Return the name at the current address.'''
    return name(ui.current.address(), **flags)
@utils.multicase(ea=six.integer_types)
def name(ea, **flags):
    """Return the name defined at the address specified by `ea`.

    If `flags` is specified, then use the specified value as the flags.
    """
    ea = interface.address.inside(ea)

    # figure out what default flags to use
    fn = idaapi.get_func(ea)

    # figure out which name function to call
    if idaapi.__version__ < 6.8:
        # if get_true_name is going to return the function's name instead of a real one, then leave it as unnamed.
        if fn and interface.range.start(fn) == ea and not flags:
            return None

        aname = idaapi.get_true_name(ea) or idaapi.get_true_name(ea, ea)
    else:
        aname = idaapi.get_ea_name(ea, flags.get('flags', idaapi.GN_LOCAL))

    # return the name at the specified address or not
    return utils.string.of(aname) or None
@utils.multicase(packed=tuple)
def name(packed, **flags):
    '''Renames the current address to the given `packed` name.'''
    return name(ui.current.address(), *packed, **flags)
@utils.multicase(string=six.string_types)
@utils.string.decorate_arguments('string', 'suffix')
def name(string, *suffix, **flags):
    '''Renames the current address to `string`.'''
    return name(ui.current.address(), string, *suffix, **flags)
@utils.multicase(none=None.__class__)
def name(none, **flags):
    '''Removes the name at the current address.'''
    return name(ui.current.address(), none or '', **flags)
@utils.multicase(packed=tuple)
def name(ea, packed, **flags):
    '''Renames the address specifed by `ea` to the given `packed` name.'''
    return name(ea, *packed, **flags)
@utils.multicase(ea=six.integer_types, string=six.string_types)
@utils.string.decorate_arguments('string', 'suffix')
def name(ea, string, *suffix, **flags):
    """Renames the address specified by `ea` to `string`.

    If `ea` is pointing to a global and is not contained by a function, then by default the label will be added to the Names list.
    If `flags` is specified, then use the specified value as the flags.
    If the boolean `listed` is specified, then specify whether to add the label to the Names list or not.
    """
    # combine name with its suffix
    res = (string,) + suffix
    string = interface.tuplename(*res)

    # validate the address, and get the original flags
    ea = interface.address.inside(ea)
    ofl = type.flags(ea)

    ## define some closures that perform the different tasks necessary to
    ## apply a name to a given address
    def apply_name(ea, string, F):
        '''Apply the name in `string` to the address `ea` with the flags specified in `F`.'''

        # convert the specified string into a form that IDA can handle
        ida_string = utils.string.to(string)

        # validate the name
        res = idaapi.validate_name2(ida_string[:]) if idaapi.__version__ < 7.0 else idaapi.validate_name(ida_string[:], idaapi.VNT_VISIBLE)
        if ida_string and ida_string != res:
            logging.info(u"{:s}.name({:#x}, \"{:s}\"{:s}) : Stripping invalid chars from specified name resulted in \"{:s}\".".format(__name__, ea, utils.string.escape(string, '"'), u", {:s}".format(utils.string.kwargs(flags)) if flags else '', utils.string.escape(utils.string.of(res), '"')))
            ida_string = res

        # fetch the old name and set the new one at the same time.
        res, ok = name(ea), idaapi.set_name(ea, ida_string or "", F)

        if not ok:
            raise E.DisassemblerError(u"{:s}.name({:#x}, \"{:s}\"{:s}) : Unable to call `idaapi.set_name({:#x}, \"{:s}\", {:#x})`.".format(__name__, ea, utils.string.escape(string, '"'), u", {:s}".format(utils.string.kwargs(flags)) if flags else '', ea, utils.string.escape(string, '"'), F))
        return res

    def name_within(ea, string, F):
        '''Add or rename the label at the address `ea` using the name in `string` with the flags in `F`.'''
        func, realname, localname = idaapi.get_func(ea), idaapi.get_visible_name(ea), idaapi.get_visible_name(ea, idaapi.GN_LOCAL)

        # if there's a public name at this address then use the
        # flags to determine how to update the public name.
        if idaapi.is_public_name(ea) or any(F & item for item in [idaapi.SN_PUBLIC, idaapi.SN_NON_PUBLIC]):
            F |= idaapi.SN_PUBLIC if F & idaapi.SN_PUBLIC else idaapi.SN_NON_PUBLIC

        # if we're pointing to the start of the function, then unless
        # public was explicitly ,specified we need to set the local name.
        elif interface.range.start(func) == ea and not builtins.all(F & item for item in [idaapi.SN_PUBLIC, idaapi.SN_NON_PUBLIC]):
            F |= idaapi.SN_LOCAL

        # if the name is supposed to be in the list, then we need to check if there's a
        # local name.
        elif not F & idaapi.SN_NOLIST:
            if localname and realname != localname:
                idaapi.del_local_name(ea), idaapi.set_name(ea, localname, idaapi.SN_NOLIST)
            F &= ~idaapi.SN_LOCAL

        # if a regular name is defined, but not a local one, then we need to set the local
        # one first.
        elif realname and realname == localname:
            F |= idaapi.SN_NOLIST

        # otherwise we're using a local name because we're inside a function.
        else:
            F |= idaapi.SN_LOCAL

        # now we can apply the name with the flags that we determined.
        return apply_name(ea, string, F)

    def name_outside(ea, string, F):
        '''Add or rename the global at the address `ea` using the name in `string` with the flags in `F`.'''
        realname, localname = idaapi.get_visible_name(ea), idaapi.get_visible_name(ea, idaapi.GN_LOCAL)

        # preserve the name if its public
        F |= idaapi.SN_PUBLIC if idaapi.is_public_name(ea) else idaapi.SN_NON_PUBLIC

        # if 'listed' wasn't explicitly specified then ensure it's
        # not listed as requested.
        if 'listed' not in flags:
            F |= idaapi.SN_NOLIST

        # then finally apply the name.
        return apply_name(ea, string, F)

    ## now we can define the actual logic for naming the given address
    flag = idaapi.SN_NON_AUTO
    flag |= idaapi.SN_NOCHECK

    # preserve any flags that were previously applied
    flag |= 0 if idaapi.is_in_nlist(ea) else idaapi.SN_NOLIST
    flag |= idaapi.SN_WEAK if idaapi.is_public_name(ea) and idaapi.is_weak_name(ea) else idaapi.SN_NON_WEAK

    # if the bool `listed` is True, then ensure that it's added to the name list.
    if 'listed' in flags:
        flag = (flag & ~idaapi.SN_NOLIST) if flags.get('listed', False) else (flag | idaapi.SN_NOLIST)

    # if custom flags were specified, then just use those as they should get
    # priority
    if 'flags' in flags:
        return apply_name(ea, string, flags['flags'])

    # if we're within a function, then use the name_within closure to apply the name
    elif function.within(ea):
        return name_within(ea, string, flag)

    # otherwise, we use the name_without closure to apply it
    return name_outside(ea, string, flag)
@utils.multicase(ea=six.integer_types, none=None.__class__)
def name(ea, none, **flags):
    '''Removes the name defined at the address `ea`.'''
    return name(ea, none or '', **flags)

@utils.multicase()
def mangled():
    '''Return the mangled name at the current address.'''
    return mangled(ui.current.address())
@utils.multicase(ea=six.integer_types)
def mangled(ea):
    '''Return the mangled name at the address specified by `ea`.'''
    MANGLED_CODE, MANGLED_DATA, MANGLED_UNKNOWN = getattr(idaapi, 'MANGLED_CODE', 0), getattr(idaapi, 'MANGLED_DATA', 1), getattr(idaapi, 'MANGLED_UNKNOWN', 2)
    Fmangled_type = idaapi.get_mangled_name_type if hasattr(idaapi, 'get_mangled_name_type') else utils.fcompose(utils.frpartial(idaapi.demangle_name, 0), utils.fcondition(operator.truth)(MANGLED_CODE if type.is_code(ea) else MANGLED_DATA, MANGLED_UNKNOWN))

    result = name(ea)
    mangled_name_type_t = Fmangled_type(utils.string.to(result))
    if mangled_name_type_t == MANGLED_UNKNOWN:
        logging.warning(u"{:s}.mangled({:#x}) : The name at the given address ({:#x}) was not mangled ({:d}) and will be the same as returning the {:s} name.".format(__name__, ea, ea, mangled_name_type_t, 'regular'))
    return result
@utils.multicase(string=six.string_types)
@utils.string.decorate_arguments('string','suffix')
def mangled(string, *suffix):
    '''Rename the current address to the mangled version of `string` and return its previous mangled value.'''
    return mangled(ui.current.address(), string, *suffix)
@utils.multicase(none=None.__class__)
def mangled(none):
    '''Remove the mangled name at the current address and return its previous mangled value.'''
    return mangled(ui.current.address(), none)
@utils.multicase(ea=six.integer_types, string=six.string_types)
@utils.string.decorate_arguments('string', 'suffix')
def mangled(ea, string, *suffix):
    '''Rename the address specified by `ea` to the mangled version of `string` and return its previous mangled value.'''
    MANGLED_CODE, MANGLED_DATA, MANGLED_UNKNOWN = getattr(idaapi, 'MANGLED_CODE', 0), getattr(idaapi, 'MANGLED_DATA', 1), getattr(idaapi, 'MANGLED_UNKNOWN', 2)
    Fmangled_type = idaapi.get_mangled_name_type if hasattr(idaapi, 'get_mangled_name_type') else utils.fcompose(utils.frpartial(idaapi.demangle_name, 0), utils.fcondition(operator.truth)(MANGLED_CODE if type.is_code(ea) else MANGLED_DATA, MANGLED_UNKNOWN))

    mangled_name_type_t = Fmangled_type(utils.string.to(string))
    if mangled_name_type_t == MANGLED_UNKNOWN:
        raise NotImplementedError(u"{:s}.mangled({:#x}, {:s}) : Unable to mangle the specified name (\"{:s}\") before applying it to the address ({:#x}).".format(__name__, ea, ', '.join(map("{!r}".format, itertools.chain([string], suffix))), utils.string.escape(string, '"'), ea))
    if suffix:
        raise NotImplementedError(u"{:s}.mangled({:#x}, {:s}) : Unable to attach the suffix (\"{:s}\") to the unmangled name (\"{:s}\") before applying it to the address ({:#x}).".format(__name__, ea, ', '.join(map("{!r}".format, itertools.chain([string], suffix))), interface.tuplename(*suffix), internal.declaration.demangle(string), ea))
    # FIXME: mangle the string that we were given according to the schema for
    #        the default compiler type with the suffix appended to its name.
    logging.warning(u"{:s}.mangled({:#x}, {:s}) : The specified name (\"{:s}\") is already mangled ({:d}) and will be assigned to the given address ({:#x}) as \"{:s}\".".format(__name__, ea, ', '.join(map("{!r}".format, itertools.chain([string], suffix))), utils.string.escape(string, '"'), mangled_name_type_t, ea, internal.declaration.demangle(string)))
    return name(ea, string, *suffix)
@utils.multicase(ea=six.integer_types, none=None.__class__)
def mangled(ea, none):
    '''Remove the name at the address specified by `ea` and return its previous mangled value.'''
    MANGLED_CODE, MANGLED_DATA, MANGLED_UNKNOWN = getattr(idaapi, 'MANGLED_CODE', 0), getattr(idaapi, 'MANGLED_DATA', 1), getattr(idaapi, 'MANGLED_UNKNOWN', 2)
    Fmangled_type = idaapi.get_mangled_name_type if hasattr(idaapi, 'get_mangled_name_type') else utils.fcompose(utils.frpartial(idaapi.demangle_name, 0), utils.fcondition(operator.truth)(MANGLED_CODE if type.is_code(ea) else MANGLED_DATA, MANGLED_UNKNOWN))
    GN_DEMANGLED = getattr(idaapi, 'GN_DEMANGLED', 0)

    flags = functools.reduce(operator.or_, [GN_DEMANGLED, idaapi.GN_SHORT])
    string, _ = name(ea), name(ea, none, flags=flags)
    mangled_name_type_t = Fmangled_type(utils.string.to(string))
    if mangled_name_type_t == MANGLED_UNKNOWN:
        logging.warning(u"{:s}.mangled({:#x}, {!s}) : The name at the given address ({:#x}) was not mangled ({:d}) and will be the same as returning the {:s} name.".format(__name__, ea, none, ea, mangled_name_type_t, 'regular'))
    return string
mangle = utils.alias(mangled)

@utils.multicase()
def unmangled():
    '''Return the name at the current address in its unmangled form.'''
    return unmangled(ui.current.address())
@utils.multicase(ea=six.integer_types)
def unmangled(ea):
    '''Return the name at the address specified by `ea` in its unmangled form.'''
    GN_DEMANGLED = getattr(idaapi, 'GN_DEMANGLED', 0)

    flags = functools.reduce(operator.or_, [GN_DEMANGLED, idaapi.GN_SHORT])
    result = name(ea, flags=flags)
    return result if hasattr(idaapi, 'GN_DEMANGLED') else internal.declaration.demangle(result)
@utils.multicase(string=six.string_types)
@utils.string.decorate_arguments('string','suffix')
def unmangled(string, *suffix):
    '''Rename the current address using the mangled version of `string` and return its previous unmangled value.'''
    return unmangled(ui.current.address(), string, *suffix)
@utils.multicase(none=None.__class__)
def unmangled(none):
    '''Remove the name at the current address and return its previous unmangled value.'''
    return unmangled(ui.current.address(), none)
@utils.multicase(ea=six.integer_types, string=six.string_types)
@utils.string.decorate_arguments('string', 'suffix')
def unmangled(ea, string, *suffix):
    '''Rename the address specified by `ea` using the mangled version of `string` and return its previous unmangled value.'''
    MANGLED_CODE, MANGLED_DATA, MANGLED_UNKNOWN = getattr(idaapi, 'MANGLED_CODE', 0), getattr(idaapi, 'MANGLED_DATA', 1), getattr(idaapi, 'MANGLED_UNKNOWN', 2)
    Fmangled_type = idaapi.get_mangled_name_type if hasattr(idaapi, 'get_mangled_name_type') else utils.fcompose(utils.frpartial(idaapi.demangle_name, 0), utils.fcondition(operator.truth)(MANGLED_CODE if type.is_code(ea) else MANGLED_DATA, MANGLED_UNKNOWN))
    GN_DEMANGLED = getattr(idaapi, 'GN_DEMANGLED', 0)

    mangled_name_type_t = Fmangled_type(utils.string.to(string))
    if mangled_name_type_t != MANGLED_UNKNOWN:
        logging.warning(u"{:s}.unmangled({:#x}, {:s}) : The specified name (\"{:s}\") is already mangled ({:d}) and will be assigned to the given address ({:#x}) as \"{:s}\".".format(__name__, ea, ', '.join(map("{!r}".format, itertools.chain([string], suffix))), utils.string.escape(string, '"'), mangled_name_type_t, ea, internal.declaration.demangle(string)))
    if suffix:
        raise NotImplementedError(u"{:s}.unmangled({:#x}, {:s}) : Unable to attach the suffix (\"{:s}\") to the unmangled name (\"{:s}\") before applying it to the address ({:#x}).".format(__name__, ea, ', '.join(map("{!r}".format, itertools.chain([string], suffix))), interface.tuplename(*suffix), internal.declaration.demangle(string), ea))
    # FIXME: correct the string, doing whatever it takes to keep it the same
    #        when it gets mangled(?) and append the given suffix to its name.
    flags = functools.reduce(operator.or_, [GN_DEMANGLED, idaapi.GN_SHORT])
    result = name(ea, string, *suffix, flags=flags)
    return result if hasattr(idaapi, 'GN_DEMANGLED') else internal.declaration.demangle(result)
@utils.multicase(ea=six.integer_types, none=None.__class__)
def unmangled(ea, none):
    '''Remove the name at the address specified by `ea` and return its previous unmangled value.'''
    MANGLED_CODE, MANGLED_DATA, MANGLED_UNKNOWN = getattr(idaapi, 'MANGLED_CODE', 0), getattr(idaapi, 'MANGLED_DATA', 1), getattr(idaapi, 'MANGLED_UNKNOWN', 2)
    Fmangled_type = idaapi.get_mangled_name_type if hasattr(idaapi, 'get_mangled_name_type') else utils.fcompose(utils.frpartial(idaapi.demangle_name, 0), utils.fcondition(operator.truth)(MANGLED_CODE if type.is_code(ea) else MANGLED_DATA, MANGLED_UNKNOWN))
    GN_DEMANGLED = getattr(idaapi, 'GN_DEMANGLED', 0)

    flags = functools.reduce(operator.or_, [GN_DEMANGLED, idaapi.GN_SHORT])
    string, result = name(ea), name(ea, none, flags=flags)
    mangled_name_type_t = Fmangled_type(utils.string.to(string))
    if mangled_name_type_t == MANGLED_UNKNOWN:
        logging.warning(u"{:s}.unmangled({:#x}, {!s}) : The name at the given address ({:#x}) was not mangled ({:d}) and will be the same as returning the {:s} name.".format(__name__, ea, none, ea, mangled_name_type_t, 'regular'))
    return result if hasattr(idaapi, 'GN_DEMANGLED') else internal.declaration.demangle(result)
unmangle = demangle = demangled = utils.alias(unmangled)

@utils.multicase()
def color():
    '''Return the color (RGB) for the item at the current address.'''
    return color(ui.current.address())
@utils.multicase(none=None.__class__)
def color(none):
    '''Remove the color from the item at the current address.'''
    return color(ui.current.address(), None)
@utils.multicase(ea=six.integer_types)
def color(ea):
    '''Return the color (RGB) for the item at the address specified by `ea`.'''
    DEFCOLOR = 0xffffffff
    res = idaapi.get_item_color(interface.address.inside(ea))
    b, r = (res&0xff0000)>>16, res&0x0000ff
    return None if res == DEFCOLOR else (r<<16)|(res&0x00ff00)|b
@utils.multicase(ea=six.integer_types, none=None.__class__)
def color(ea, none):
    '''Remove the color from the item at the the address specified by `ea`.'''
    DEFCOLOR = 0xffffffff
    res, void = color(ea), idaapi.set_item_color(interface.address.inside(ea), DEFCOLOR)
    return res
@utils.multicase(ea=six.integer_types, rgb=six.integer_types)
def color(ea, rgb):
    '''Set the color for the item at address `ea` to `rgb`.'''
    r, b = (rgb&0xff0000) >> 16, rgb&0x0000ff
    res, void = color(ea), idaapi.set_item_color(interface.address.inside(ea), (b<<16)|(rgb&0x00ff00)|r)
    return res

@utils.multicase()
def comment(**repeatable):
    '''Return the comment at the current address.'''
    return comment(ui.current.address(), **repeatable)
@utils.multicase(ea=six.integer_types)
def comment(ea, **repeatable):
    """Return the comment at the address `ea`.

    If the bool `repeatable` is specified, then return the repeatable comment.
    """
    res = idaapi.get_cmt(interface.address.inside(ea), repeatable.get('repeatable', False))

    # return the string in a format the user can process
    return utils.string.of(res)
@utils.multicase(string=six.string_types)
@utils.string.decorate_arguments('string')
def comment(string, **repeatable):
    '''Set the comment at the current address to `string`.'''
    return comment(ui.current.address(), string, **repeatable)
@utils.multicase(none=None.__class__)
def comment(none, **repeatable):
    '''Remove the comment at the current address.'''
    return comment(ui.current.address(), none or '', **repeatable)
@utils.multicase(ea=six.integer_types, string=six.string_types)
@utils.string.decorate_arguments('string')
def comment(ea, string, **repeatable):
    """Set the comment at the address `ea` to `string`.

    If the bool `repeatable` is specified, then modify the repeatable comment.
    """
    # apply the comment to the specified address
    res, ok = comment(ea, **repeatable), idaapi.set_cmt(interface.address.inside(ea), utils.string.to(string), repeatable.get('repeatable', False))
    if not ok:
        raise E.DisassemblerError(u"{:s}.comment({:#x}, {!r}{:s}) : Unable to call `idaapi.set_cmt({:#x}, \"{:s}\", {!s})`.".format(__name__, ea, string, u", {:s}".format(utils.string.kwargs(repeatable)) if repeatable else '', ea, utils.string.escape(string, '"'), repeatable.get('repeatable', False)))
    return res
@utils.multicase(ea=six.integer_types, none=None.__class__)
def comment(ea, none, **repeatable):
    """Remove the comment at the address `ea`.

    If the bool `repeatable` is specified, then remove the repeatable comment.
    """
    return comment(ea, none or '', **repeatable)

class entries(object):
    """
    This namespace can be used to enumerate all of the entry points and
    exports that are defined within the database By default the address
    of each entrypoint will be yielded.

    This namespace is also aliased as ``database.exports``.

    When listing entry points that are matched, the following legend can be
    used to identify certain characteristics about them:

        `F` - The entry point is referencing a function
        `C` - The entry point is referencing code
        `A` - The entry point is referencing data (address)
        `D` - The entry point is referencing a decompiled function
        `T` - The address of the entry point has a type applied to it
        `t` - The address of the entry point has a guessable type
        `C` - The address of the entry point is marked as code
        `D` - The address of the entry point is marked as data
        `^` - The address of the entry point is marked as unknown
        `+` - The entry point has an implicit tag applied to it (named or typed)
        `*` - The entry point has an explicit tag applied to it

    The different types that one can match entrypoints with are the following:

        `address` or `ea` - Match according to the entrypoint's address
        `name` - Match according to the exact name
        `like` - Filter the entrypoint names according to a glob
        `regex` - Filter the entrypoint names according to a regular-expression
        `index` - Match according to the entrypoint's index
        `ordinal` - Match according to the entrypoint's ordinal
        `greater` or `ge` - Filter the entrypoints for any after the specified address (inclusive)
        `gt` - Filter the entrypoints for any after the specified address (exclusive)
        `less` or `le` - Filter the entrypoints for any before the specified address (inclusive)
        `lt` - Filter the entrypoints for any before the specified address (exclusive)
        `function` - Filter the entrypoints for any that are referencing a function
        `typed` - Filter the entrypoints for any that have type information applied to them
        `tagged` - Filter the entrypoints for any that use the specified tag(s)
        `predicate` - Filter the entrypoints by passing its index (ordinal) to a callable

    Some examples of using these keywords are as follows::

        > database.entries.list(greater=h())
        > iterable = database.entries.iterate(like='Nt*')
        > result = database.entries.search(index=0)

    """

    __matcher__ = utils.matcher()
    __matcher__.boolean('address', operator.eq, idaapi.get_entry_ordinal, idaapi.get_entry)
    __matcher__.boolean('ea', operator.eq, idaapi.get_entry_ordinal, idaapi.get_entry)
    __matcher__.boolean('greater', operator.le, idaapi.get_entry_ordinal, idaapi.get_entry)
    __matcher__.boolean('ge', operator.le, idaapi.get_entry_ordinal, idaapi.get_entry)
    __matcher__.boolean('gt', operator.lt, idaapi.get_entry_ordinal, idaapi.get_entry)
    __matcher__.boolean('less', operator.ge, idaapi.get_entry_ordinal, idaapi.get_entry)
    __matcher__.boolean('le', operator.ge, idaapi.get_entry_ordinal, idaapi.get_entry)
    __matcher__.boolean('lt', operator.gt, idaapi.get_entry_ordinal, idaapi.get_entry)
    __matcher__.boolean('name', lambda name, item: name.lower() == item.lower(), idaapi.get_entry_ordinal, idaapi.get_entry_name, utils.fdefault(''), utils.string.of)
    __matcher__.combinator('like', utils.fcompose(fnmatch.translate, utils.fpartial(re.compile, flags=re.IGNORECASE), operator.attrgetter('match')), idaapi.get_entry_ordinal, idaapi.get_entry_name, utils.fdefault(''), utils.string.of)
    __matcher__.combinator('regex', utils.fcompose(utils.fpartial(re.compile, flags=re.IGNORECASE), operator.attrgetter('match')), idaapi.get_entry_ordinal, idaapi.get_entry_name, utils.fdefault(''), utils.string.of)
    __matcher__.mapping('function', function.within, idaapi.get_entry_ordinal, idaapi.get_entry)
    __matcher__.mapping('typed', operator.truth, idaapi.get_entry_ordinal, idaapi.get_entry, lambda ea: idaapi.get_tinfo2(ea, idaapi.tinfo_t()) if idaapi.__version__ < 7.0 else idaapi.get_tinfo(idaapi.tinfo_t(), ea))
    __matcher__.boolean('tagged', lambda parameter, keys: operator.truth(keys) == parameter if isinstance(parameter, bool) else operator.contains(keys, parameter) if isinstance(parameter, six.string_types) else keys&parameter, idaapi.get_entry_ordinal, idaapi.get_entry, lambda ea: function.tag(ea) if function.within(ea) else tag(ea), operator.methodcaller('keys'), builtins.set)
    __matcher__.predicate('predicate', idaapi.get_entry_ordinal),
    __matcher__.predicate('pred', idaapi.get_entry_ordinal)
    __matcher__.boolean('ordinal', operator.eq, idaapi.get_entry_ordinal)
    __matcher__.boolean('index', operator.eq)

    def __new__(cls):
        '''Yield the address of each entry point defined within the database.'''
        for ea in cls.iterate():
            yield ea
        return

    @utils.multicase(string=six.string_types)
    @classmethod
    @utils.string.decorate_arguments('string')
    def __iterate__(cls, string):
        return cls.__iterate__(like=string)
    @utils.multicase()
    @classmethod
    @utils.string.decorate_arguments('name', 'like', 'regex')
    def __iterate__(cls, **type):
        listable = builtins.range(idaapi.get_entry_qty())
        for key, value in (type or {'predicate': utils.fconstant(True)}).items():
            listable = [item for item in cls.__matcher__.match(key, value, listable)]
        for item in listable: yield item

    @utils.multicase(string=six.string_types)
    @classmethod
    @utils.string.decorate_arguments('string')
    def iterate(cls, string):
        '''Iterate through all of the entry points in the database with a glob that matches `string`.'''
        return cls.iterate(like=string)
    @utils.multicase()
    @classmethod
    @utils.string.decorate_arguments('name', 'like', 'regex')
    def iterate(cls, **type):
        '''Iterate through all of the entry points in the database that match the keyword specified by `type`.'''
        for ea in cls.__iterate__(**type):
            yield cls.__address__(ea)
        return

    @classmethod
    def __index__(cls, ea):
        '''Return the index of the entry point at the specified `address`.'''
        f = utils.fcompose(idaapi.get_entry_ordinal, idaapi.get_entry)

        # Iterate through each entry point, and yield a tuple containing its address and index.
        Ftransform = utils.fcompose(utils.fmap(f, lambda item: item), builtins.tuple)
        iterable = (Ftransform(item) for item in builtins.range(idaapi.get_entry_qty()))

        # Iterate through each (address, index) looking for the matching address.
        Fcrit = utils.fcompose(operator.itemgetter(0), functools.partial(operator.eq, ea))
        filterable = (item for item in iterable if Fcrit(item))

        # Return the index of the address that matched.
        iterable = (index for _, index in filterable)
        return builtins.next(iterable, None)

    @classmethod
    def __address__(cls, index):
        '''Return the address of the entry point at the specified `index`.'''
        res = cls.__entryordinal__(index)
        res = idaapi.get_entry(res)
        return None if res == idaapi.BADADDR else res

    # Return the name of the entry point at the specified `index`.
    __entryname__ = staticmethod(utils.fcompose(idaapi.get_entry_ordinal, idaapi.get_entry_name, utils.fdefault(''), utils.string.of))
    # Return the ordinal of the entry point at the specified `index`.
    __entryordinal__ = staticmethod(idaapi.get_entry_ordinal)

    @utils.multicase()
    @classmethod
    def ordinal(cls):
        '''Return the ordinal of the entry point at the current address.'''
        return cls.ordinal(ui.current.address())
    @utils.multicase(ea=six.integer_types)
    @classmethod
    def ordinal(cls, ea):
        '''Return the ordinal of the entry point at the address `ea`.'''
        res = cls.__index__(ea)
        if res is not None:
            return cls.__entryordinal__(res)
        raise E.MissingTypeOrAttribute(u"{:s}.ordinal({:#x}) : No entry point at specified address.".format('.'.join([__name__, cls.__name__]), ea))

    @utils.multicase()
    @classmethod
    def name(cls):
        '''Return the name of the entry point at the current address.'''
        return cls.name(ui.current.address())
    @utils.multicase(ea=six.integer_types)
    @classmethod
    def name(cls, ea):
        '''Return the name of the entry point at the address `ea`.'''
        res = cls.__index__(ea)
        if res is not None:
            return cls.__entryname__(res)
        raise E.MissingTypeOrAttribute(u"{:s}.name({:#x}) : No entry point at specified address.".format('.'.join([__name__, cls.__name__]), ea))

    @utils.multicase(string=six.string_types)
    @classmethod
    @utils.string.decorate_arguments('string')
    def list(cls, string):
        '''List all of the entry points matching the glob `string` against the name.'''
        return cls.list(like=string)
    @utils.multicase()
    @classmethod
    @utils.string.decorate_arguments('name', 'like', 'regex')
    def list(cls, **type):
        '''List all of the entry points in the database that match the keyword specified by `type`.'''
        MANGLED_CODE, MANGLED_DATA, MANGLED_UNKNOWN = getattr(idaapi, 'MANGLED_CODE', 0), getattr(idaapi, 'MANGLED_DATA', 1), getattr(idaapi, 'MANGLED_UNKNOWN', 2)
        Fmangled_type = idaapi.get_mangled_name_type if hasattr(idaapi, 'get_mangled_name_type') else utils.fcompose(utils.frpartial(idaapi.demangle_name, 0), utils.fcondition(operator.truth)(MANGLED_CODE, MANGLED_UNKNOWN))
        MNG_NODEFINIT, MNG_NOPTRTYP, MNG_LONG_FORM = getattr(idaapi, 'MNG_NODEFINIT', 8), getattr(idaapi, 'MNG_NOPTRTYP', 7), getattr(idaapi, 'MNG_LONG_FORM', 0x6400007)
        MNG_NOSCTYP, MNG_NOCALLC = getattr(idaapi, 'MNG_NOSCTYP', 0x400), getattr(idaapi, 'MNG_NOCALLC', 0x100)

        # Set some reasonable defaults
        maxindex = maxaddr = maxordinal = 0

        # First pass through our listable grabbing the maximum lengths of our fields
        listable = []
        for index in cls.__iterate__(**type):
            maxindex = max(index, maxindex)

            res = idaapi.get_entry_ordinal(index)
            maxaddr = max(idaapi.get_entry(res), maxaddr)
            maxordinal = max(res, maxordinal)

            listable.append(index)

        # Collect the maximum sizes for everything from the first pass
        cindex, cordinal = (utils.string.digits(maxindex, 10) for item in [maxindex, maxordinal])
        caddr = utils.string.digits(maxaddr, 16)

        # List all the fields from everything that matched
        get_tinfo = (lambda ti, ea: idaapi.get_tinfo2(ea, ti)) if idaapi.__version__ < 7.0 else idaapi.get_tinfo
        for index in listable:
            ordinal = cls.__entryordinal__(index)
            ea = idaapi.get_entry(ordinal)
            tags = function.tag(ea) if function.within(ea) else tag(ea)
            realname = cls.__entryname__(index) or name(ea)

            # Some flags that could be useful.
            fclass = 'A' if t.is_data(ea) or t.is_unknown(ea) else 'D' if function.within(ea) and function.type.is_decompiled(ea) else 'F' if function.within(ea) else 'C' if t.is_code(ea) else '-'
            finitialized = '-' if not t.is_initialized(ea) else 'C' if t.is_code(ea) else 'D' if t.is_data(ea) else '^'
            ftyped = 'T' if get_tinfo(idaapi.tinfo_t(), ea) else 't' if t.has_typeinfo(ea) else '-'
            tags.pop('__name__', None)
            ftagged = '-' if not tags else '*' if any(not item.startswith('__') for item in tags) else '+'
            flags = itertools.chain(fclass, finitialized, ftyped, ftagged)

            # If we're within a function, then display the type information if available
            # while being aware of name mangling. If there's no type information, then
            # use the unmangled name for displaying the export.
            if function.within(ea):
                ti, mangled_name_type_t = idaapi.tinfo_t(), Fmangled_type(utils.string.to(realname))
                dname = realname if mangled_name_type_t == MANGLED_UNKNOWN else utils.string.of(idaapi.demangle_name(utils.string.to(realname), MNG_NODEFINIT|MNG_NOPTRTYP) or realname)
                demangled = utils.string.of(idaapi.demangle_name(utils.string.to(realname), MNG_LONG_FORM|MNG_NOSCTYP|MNG_NOCALLC)) or realname
                description = idaapi.print_tinfo('', 0, 0, idaapi.PRTYPE_DEF, ti, utils.string.to(dname), '') if get_tinfo(ti, ea) else demangled

            # Otherwise, we always try to display the type regardless of what's available.
            else:
                description = tags.get('__typeinfo__', realname)
            six.print_(u"{:<{:d}s} {:s} {:<#{:d}x} : {:s} : {:s}".format("[{:d}]".format(index), 2 + math.trunc(cindex), "{:>{:d}s}".format('' if ea == ordinal else "(#{:d})".format(ordinal), 2 + 1 + math.trunc(cindex)), ea, 2 + math.trunc(caddr), ''.join(flags), description))
        return

    @utils.multicase(string=six.string_types)
    @classmethod
    @utils.string.decorate_arguments('string')
    def search(cls, string):
        '''Search through all of the entry point names matching the glob `string` and return the first result.'''
        return cls.search(like=string)
    @utils.multicase()
    @classmethod
    @utils.string.decorate_arguments('name', 'like', 'regex')
    def search(cls, **type):
        '''Search through all of the entry points within the database and return the first result matching the keyword specified by `type`.'''
        query_s = utils.string.kwargs(type)

        listable = [item for item in cls.__iterate__(**type)]
        if len(listable) > 1:
            messages = ((u"[{:d}] ({:s}) {:#x} : {:s} {:s}".format(idx, '' if ordinal == ea else "#{:d}".format(ordinal), ea, '[FUNC]' if function.within(ea) else '[ADDR]', name or unmangled(ea))) for idx, ordinal, name, ea in map(utils.fmap(utils.fidentity, cls.__entryordinal__, cls.__entryname__, cls.__address__), listable))
            [ logging.info(msg) for msg in messages ]
            f = utils.fcompose(idaapi.get_entry_ordinal, idaapi.get_entry)
            logging.warning(u"{:s}.search({:s}) : Found {:d} matching results, Returning the first entry point at {:#x}.".format('.'.join([__name__, cls.__name__]), query_s, len(listable), f(listable[0])))

        iterable = (item for item in listable)
        res = builtins.next(iterable, None)
        if res is None:
            raise E.SearchResultsError(u"{:s}.search({:s}) : Found 0 matching results.".format('.'.join([__name__, cls.__name__]), query_s))
        return cls.__address__(res)

    @utils.multicase()
    @classmethod
    def new(cls):
        '''Makes an entry point at the current address.'''
        ea, entryname, ordinal = ui.current.address(), name(ui.current.address()) or function.name(ui.current.address()), idaapi.get_entry_qty()
        if entryname is None:
            raise E.MissingTypeOrAttribute(u"{:s}.new({:#x}) : Unable to determine name at address.".format( '.'.join([__name__, cls.__name__]), ea))
        return cls.new(ea, entryname, ordinal)
    @utils.multicase(ea=six.integer_types)
    @classmethod
    def new(cls, ea):
        '''Makes an entry point at the specified address `ea`.'''
        entryname, ordinal = name(ea) or function.name(ea), idaapi.get_entry_qty()
        if entryname is None:
            raise E.MissingTypeOrAttribute(u"{:s}.new({:#x}) : Unable to determine name at address.".format( '.'.join([__name__, cls.__name__]), ea))
        return cls.new(ea, entryname, ordinal)
    @utils.multicase(name=six.string_types)
    @classmethod
    @utils.string.decorate_arguments('name')
    def new(cls, name):
        '''Adds the current address as an entry point using `name` and the next available index as the ordinal.'''
        return cls.new(ui.current.address(), name, idaapi.get_entry_qty())
    @utils.multicase(ea=six.integer_types, name=six.string_types)
    @classmethod
    @utils.string.decorate_arguments('name')
    def new(cls, ea, name):
        '''Makes the specified address `ea` an entry point having the specified `name`.'''
        ordinal = idaapi.get_entry_qty()
        return cls.new(ea, name, ordinal)
    @utils.multicase(name=six.string_types, ordinal=six.integer_types)
    @classmethod
    @utils.string.decorate_arguments('name')
    def new(cls, name, ordinal):
        '''Adds an entry point with the specified `name` to the database using `ordinal` as its index.'''
        return cls.new(ui.current.address(), name, ordinal)
    @utils.multicase(ea=six.integer_types, name=six.string_types, ordinal=six.integer_types)
    @classmethod
    @utils.string.decorate_arguments('name')
    def new(cls, ea, name, ordinal):
        '''Adds an entry point at `ea` with the specified `name` and `ordinal`.'''
        res = idaapi.add_entry(ordinal, interface.address.inside(ea), utils.string.to(name), 0)
        ui.state.wait()
        return res

    add = utils.alias(new, 'entries')
exports = entries     # XXX: ns alias

def tags():
    '''Return all of the tag names used globally within the database.'''
    return internal.comment.globals.name()

@utils.multicase()
def tag():
    '''Return all of the tags defined at the current address.'''
    return tag(ui.current.address())
@utils.multicase(ea=six.integer_types)
def tag(ea):
    '''Return all of the tags defined at address `ea`.'''
    MANGLED_CODE, MANGLED_DATA, MANGLED_UNKNOWN = getattr(idaapi, 'MANGLED_CODE', 0), getattr(idaapi, 'MANGLED_DATA', 1), getattr(idaapi, 'MANGLED_UNKNOWN', 2)
    Fmangled_type = idaapi.get_mangled_name_type if hasattr(idaapi, 'get_mangled_name_type') else utils.fcompose(utils.frpartial(idaapi.demangle_name, 0), utils.fcondition(operator.truth)(0, MANGLED_UNKNOWN))
    MNG_NODEFINIT, MNG_NOPTRTYP = getattr(idaapi, 'MNG_NODEFINIT', 8), getattr(idaapi, 'MNG_NOPTRTYP', 7)

    ea = interface.address.inside(ea)

    # Check if we're within a function and determine whether it's a
    # runtime-linked address or not. If we're within a function, then
    # we need to ensure that we're using non-repeatable comments.
    try:
        func = function.by_address(ea)
        rt, _ = interface.addressOfRuntimeOrStatic(func)

    # If the address is not within a function, then assign some variables
    # so that we will use a repeatable comment.
    except E.FunctionNotFoundError:
        rt, func = False, None
    repeatable = False if func and function.within(ea) and not rt else True

    # Read both repeatable and non-repeatable comments from the chosen
    # address so that we can decode both of them into dictionaries to
    # use. We also decode the (repeatable) function comment, because in
    # some cases a function is created for a runtime-linked address.
    res = comment(ea, repeatable=False)
    d1 = internal.comment.decode(res)
    res = comment(ea, repeatable=True)
    d2 = internal.comment.decode(res)
    res = function.comment(ea, repeatable=True) if rt else ''
    d3 = internal.comment.decode(res)

    # Check if the address had content in either decoding types of
    # comments so that we can warn the user about it.
    if six.viewkeys(d1) & six.viewkeys(d2):
        logging.info(u"{:s}.tag({:#x}) : Contents of both the repeatable and non-repeatable comment conflict with one another due to using the same keys ({:s}). Giving the {:s} comment priority.".format(__name__, ea, ', '.join(six.viewkeys(d1) & six.viewkeys(d2)), 'repeatable' if repeatable else 'non-repeatable'))
    if rt and (six.viewkeys(d3) & six.viewkeys(d1) or six.viewkeys(d3) & six.viewkeys(d2)):
        logging.info(u"{:s}.tag({:#x}) : Contents of the runtime-linked comment conflict with one of the database comments due to using the same keys ({:s}). Giving the {:s} comment priority.".format(__name__, ea, ', '.join(six.viewkeys(d3) & six.viewkeys(d2) or six.viewkeys(d3) & six.viewkeys(d1)), 'function'))

    # Merge all of the decoded tags into a dictionary while giving priority
    # to the correct one. If the address was pointing to a runtime-linked
    # address and was a case that had a function comment, then we need to
    # give those tags absolute priority when building our dictionary.
    res = {}
    [res.update(d) for d in ([d1, d2] if repeatable else [d2, d1])]
    rt and res.update(d3)

    # First thing we need to figure out is whether the name exists and if
    # it's actually special in that we need to demangle it for the real name.
    aname = name(ea)
    if aname and Fmangled_type(utils.string.to(aname)) != MANGLED_UNKNOWN:
        realname = utils.string.of(idaapi.demangle_name(utils.string.to(aname), MNG_NODEFINIT|MNG_NOPTRTYP) or aname)
    else:
        realname = aname or ''

    # Add any of the implicit tags for the specified address to our results.
    if aname and type.flags(ea, idaapi.FF_NAME): res.setdefault('__name__', realname)
    eprefix = extra.__get_prefix__(ea)
    if eprefix is not None: res.setdefault('__extra_prefix__', eprefix)
    esuffix = extra.__get_suffix__(ea)
    if esuffix is not None: res.setdefault('__extra_suffix__', esuffix)
    col = color(ea)
    if col is not None: res.setdefault('__color__', col)

    # If there was some type information associated with the address, then
    # we need its name so that we can format it and add it as an implicit tag.
    try:
        if type.has_typeinfo(ea):
            ti = type(ea)

            # Filter the name we're going to render with so that it can be parsed properly.
            valid = {item for item in string.digits} | {':'}
            filtered = str().join(item if item in valid or idaapi.is_valid_typename(utils.string.to(item)) else '_' for item in realname)
            validname = ''.join(filtered)

            # Demangle just the name if it's mangled in some way, and use it to render
            # the typeinfo to return.
            ti_s = idaapi.print_tinfo('', 0, 0, 0, ti, utils.string.to(validname), '')

            # Add it to our dictionary that we return to the user.
            res.setdefault('__typeinfo__', ti_s)

    # If we caught an exception, then the name from the type information could be
    # mangled and so we need to rip the type information directly out of the name.
    except E.InvalidTypeOrValueError:
        demangled = internal.declaration.demangle(aname)

        # if the demangled name is different from the actual name, then we need
        # to extract its result type and prepend it to the demangled name.
        if demangled != aname:
            res.setdefault('__typeinfo__', demangled)

    # Finally we can return what the user cares about.
    return res
@utils.multicase(key=six.string_types)
@utils.string.decorate_arguments('key')
def tag(key):
    '''Return the tag identified by `key` at the current address.'''
    return tag(ui.current.address(), key)
@utils.multicase(key=six.string_types)
@utils.string.decorate_arguments('key', 'value')
def tag(key, value):
    '''Set the tag identified by `key` to `value` at the current address.'''
    return tag(ui.current.address(), key, value)
@utils.multicase(ea=six.integer_types, key=six.string_types)
@utils.string.decorate_arguments('key')
def tag(ea, key):
    '''Return the tag identified by `key` from the address `ea`.'''
    res = tag(ea)
    if key in res:
        return res[key]
    raise E.MissingTagError(u"{:s}.tag({:#x}, {!r}) : Unable to read tag (\"{:s}\") from address.".format(__name__, ea, key, utils.string.escape(key, '"')))
@utils.multicase(ea=six.integer_types, key=six.string_types)
@utils.string.decorate_arguments('key', 'value')
def tag(ea, key, value):
    '''Set the tag identified by `key` to `value` at the address `ea`.'''
    if value is None:
        raise E.InvalidParameterError(u"{:s}.tag({:#x}, {!r}, {!r}) : Tried to set the tag (\"{:s}\") to an unsupported type {!r}.".format(__name__, ea, key, value, utils.string.escape(key, '"'), value))

    # If any of the supported implicit tags were specified, then figure out which
    # one and using it to dispatch to the correct handler.
    if key == '__name__':
        return name(ea, value, listed=True)
    elif key == '__extra_prefix__':
        return extra.__set_prefix__(ea, value)
    elif key == '__extra_suffix__':
        return extra.__set_suffix__(ea, value)
    elif key == '__color__':
        return color(ea, value)
    elif key == '__typeinfo__':
        return type(ea, value)

    # If we're within a function, then we also need to determine whether it's a
    # runtime-linked address or not. This is because if it's a runtime-linked
    # address then a repeatable comment is used. Otherwise we encode the tags
    # within a non-repeatable comment.
    try:
        func = function.by_address(ea)
        rt, _ = interface.addressOfRuntimeOrStatic(func)

    # If the address was not within a function, then set the necessary variables
    # so that a repeatable comment is used.
    except E.FunctionNotFoundError:
        rt, func = False, None

    # If we're outside a function or pointing to a runtime-linked address, then
    # we use a repeatable comment. Anything else means a non-repeatable comment.
    repeatable = False if func and function.within(ea) and not rt else True

    # Go ahead and decode the tags that are written to all 3 comment types. This
    # way we can search them for the correct one that the user is trying to modify.
    ea = interface.address.inside(ea)
    state_correct = internal.comment.decode(comment(ea, repeatable=repeatable))
    state_wrong = internal.comment.decode(comment(ea, repeatable=not repeatable))
    state_runtime = internal.comment.decode(function.comment(ea, repeatable=True)) if func else {}

    # Now we just need to figure out which one of the dictionaries that we decoded
    # contains the key that the user is trying to modify. We need to specially
    # handle the case where the address is actually referring to a runtime address.
    if rt:
        rt, state, where = (True, state_runtime, True) if key in state_runtime else (False, state_wrong, False) if key in state_wrong else (True, state_runtime, True)
    else:
        state, where = (state_correct, repeatable) if key in state_correct else (state_wrong, not repeatable) if key in state_wrong else (state_correct, repeatable)

    # If the key was not in any of the encoded dictionaries, then we need to
    # update the reference count in the tag cache. If the address is a runtime
    # address or outside a function, then it's a global tag. Otherwise if it's
    # within a function, then it's a contents tag that we need to adjust.
    if key not in state:
        if func and function.within(ea) and not rt:
            internal.comment.contents.inc(ea, key)
        else:
            internal.comment.globals.inc(ea, key)

    # Grab the previous value from the correct dictionary that we discovered,
    # and update it with the new value that the user is modifying it with.
    res, state[key] = state.get(key, None), value

    # Now we can finally update the comment in the database. However, we need
    # to guard the modification so that the hooks don't interfere with the
    # references that we updated. We guard this situation by disabling the hooks.
    hooks = {'changing_cmt', 'cmt_changed', 'changing_range_cmt', 'range_cmt_changed', 'changing_area_cmt', 'area_cmt_changed'} & {target for target in ui.hook.idb}
    try:
        [ ui.hook.idb.disable(item) for item in hooks ]

    # If an exception was raised while disabling the hooks, then we need to bail.
    except Exception:
        raise

    # Finally we can actually encode the dictionary and write it to the address
    # the user specified using the correct comment type.
    else:
        function.comment(ea, internal.comment.encode(state), repeatable=where) if rt else comment(ea, internal.comment.encode(state), repeatable=where)

    # Lastly we release the hooks now that we've finished modifying the comment.
    finally:
        [ ui.hook.idb.enable(item) for item in hooks ]

    # Now we can return the result the user asked us for.
    return res
@utils.multicase(key=six.string_types, none=None.__class__)
def tag(key, none):
    '''Remove the tag identified by `key` from the current address.'''
    return tag(ui.current.address(), key, none)
@utils.multicase(ea=six.integer_types, key=six.string_types, none=None.__class__)
@utils.string.decorate_arguments('key')
def tag(ea, key, none):
    '''Removes the tag identified by `key` at the address `ea`.'''
    ea = interface.address.inside(ea)

    # If any of the supported implicit tags were specified, then dispatch to
    # the correct function in order to properly clear it.
    if key == '__name__':
        return name(ea, None, listed=True)
    elif key == '__extra_prefix__':
        return extra.__delete_prefix__(ea)
    elif key == '__extra_suffix__':
        return extra.__delete_suffix__(ea)
    elif key == '__typeinfo__':
        return type(ea, None)
    elif key == '__color__':
        return color(ea, None)

    # If we're within a function, then we need to distinguish whether the
    # address is a runtime-linked one or not. This way we can determine the
    # actual comment type that will be used.
    try:
        func = function.by_address(ea)
        rt, _ = interface.addressOfRuntimeOrStatic(func)

    # If the address wasn't within a function, then assign the necessary
    # values to the variables so that a repeatable comment gets used.
    except E.FunctionNotFoundError:
        rt, func = False, None

    # If we're outside a function or pointing to a runtime-linked address, then
    # a repeatable comment gets used. Inside a function is always a non-repeatable.
    repeatable = False if func and function.within(ea) and not rt else True

    # figure out which comment type the user's key is in so that we can remove
    # that one. if we're a runtime-linked address, then we need to remove the
    # tag from a repeatable function comment. if the tag isn't in any of them,
    # then it doesn't really matter since we're going to raise an exception anyways.

    # Now we decode the tags from are written to all 3 available comment types.
    # This way we can search for the correct one that the user is going to modify.
    state_correct = internal.comment.decode(comment(ea, repeatable=repeatable))
    state_wrong = internal.comment.decode(comment(ea, repeatable=not repeatable))
    state_runtime = internal.comment.decode(function.comment(ea, repeatable=True)) if func else {}

    # Then we need to figure out which one of the decoded dictionaries contains
    # the key that the user is trying to remove. The case where a runtime-linked
    # address is being referenced needs to be specially handled as IDA may
    # incorrectly declare some runtime-linked addresses as functions.
    if rt:
        rt, state, where = (True, state_runtime, True) if key in state_runtime else (False, state_wrong, False) if key in state_wrong else (True, state_runtime, True)
    else:
        state, where = (state_correct, repeatable) if key in state_correct else (state_wrong, not repeatable) if key in state_wrong else (state_correct, repeatable)

    # If the key is not in the expected dictionary, then raise an exception. If
    # it is, then we can modify the dictionary and remove it to return to the user.
    if key not in state:
        raise E.MissingTagError(u"{:s}.tag({:#x}, {!r}, {!s}) : Unable to remove non-existent tag \"{:s}\" from address.".format(__name__, ea, key, none, utils.string.escape(key, '"')))
    res = state.pop(key)

    # Now we can do our update and encode our modified dictionary, but we need
    # to guard the modification so that the hooks don't also interfere with the
    # references that we're updating. We guard by disabling the relevant hooks.
    hooks = {'changing_cmt', 'cmt_changed', 'changing_range_cmt', 'range_cmt_changed', 'changing_area_cmt', 'area_cmt_changed'} & {target for target in ui.hook.idb}
    try:
        [ ui.hook.idb.disable(item) for item in hooks ]

    # If an exception was raised while disabling the hooks, then simply bail.
    except Exception:
        raise

    # Finally we can encode the dictionary that we removed the key from and
    # write it to the correct comment at the address that the user specified.
    else:
        function.comment(ea, internal.comment.encode(state), repeatable=where) if rt else comment(ea, internal.comment.encode(state), repeatable=where)

    # Release our hooks once we've finished updating the comment.
    finally:
        [ ui.hook.idb.enable(item) for item in hooks ]

    # Now that we've removed the key from the tag and updated the comment,
    # we need to remove its reference. If the address is a runtime address
    # or outside a function, then it's a global tag being removed. Otherwise
    # it's within a function and thus a contents tag being removed.
    if func and function.within(ea) and not rt:
        internal.comment.contents.dec(ea, key)
    else:
        internal.comment.globals.dec(ea, key)

    # Finally we can return the value of the tag that was removed.
    return res

@utils.multicase(tag=six.string_types)
@utils.string.decorate_arguments('And', 'Or')
def select(tag, *And, **boolean):
    '''Query all of the global tags in the database for the specified `tag` and any others specified as `And`.'''
    res = {tag} | {item for item in And}
    boolean['And'] = {item for item in boolean.get('And', [])} | res
    return select(**boolean)
@utils.multicase()
@utils.string.decorate_arguments('And', 'Or')
def select(**boolean):
    """Query all the global tags for any tags specified by `boolean`. Yields each address found along with the matching tags as a dictionary.

    If `And` contains an iterable then require the returned address contains them.
    If `Or` contains an iterable then include any other tags that are specified.
    """
    containers = (builtins.tuple, builtins.set, builtins.list)
    boolean = {key : {item for item in value} if isinstance(value, containers) else {value} for key, value in boolean.items()}

    # Nothing specific was queried, so just yield all tags that are available.
    if not boolean:
        for ea in internal.comment.globals.address():
            ui.navigation.set(ea)
            Ftag, owners = (function.tag, {f for f in function.chunk.owners(ea)}) if function.within(ea) else (tag, {ea})
            tags = Ftag(ea)
            if tags and ea in owners: yield ea, tags
            elif ea not in owners: logging.info(u"{:s}.select() : Refusing to yield {:d} global tag{:s} for {:s} ({:#x}) possibly due to cache inconsistency as it is not referencing one of the candidate locations ({:s}).".format(__name__, len(tags), '' if len(tags) == 1 else 's', 'function address' if function.within(ea) else 'address', ea, ', '.join(map("{:#x}".format, owners))))
        return

    # Collect the tagnames to query as specified by the user.
    Or, And = ({item for item in boolean.get(B, [])} for B in ['Or', 'And'])

    # Walk through every tagged address so we can cross-check them with the query.
    for ea in internal.comment.globals.address():
        collected, _ = {}, ui.navigation.set(ea)
        Ftag, owners = (function.tag, {f for f in function.chunk.owners(ea)}) if function.within(ea) else (tag, {ea})
        tags = Ftag(ea)

        # Or(|) includes any of the tagnames that were queried.
        collected.update({key : value for key, value in tags.items() if key in Or})

        # And(&) includes any tags that include all of the queried tagnames.
        if And:
            if And & six.viewkeys(tags) == And:
                collected.update({key : value for key, value in tags.items() if key in And})
            else: continue

        # If we collected anything (matches), then yield the address and the matching tags.
        if collected and ea in owners: yield ea, collected
        elif ea not in owners: logging.info(u"{:s}.select({:s}) : Refusing to select from {:d} global tag{:s} for {:s} ({:#x}) possibly due to cache inconsistency as it is not referencing one of the candidate locations ({:s}).".format(__name__, utils.string.kwargs(boolean), len(tags), '' if len(tags) == 1 else 's', 'function address' if function.within(ea) else 'address', ea, ', '.join(map("{:#x}".format, owners))))
    return

@utils.multicase(tag=six.string_types)
@utils.string.decorate_arguments('tag', 'And', 'Or')
def selectcontents(tag, *Or, **boolean):
    '''Query all function contents for the specified `tag` or any others specified as `Or`.'''
    res = {tag} | {item for item in Or}
    boolean['Or'] = {item for item in boolean.get('Or', [])} | res
    return selectcontents(**boolean)
@utils.multicase()
@utils.string.decorate_arguments('And', 'Or')
def selectcontents(**boolean):
    """Query all function contents for any tags specified by `boolean`. Yields each function and the tags that match as a set.

    If `And` contains an iterable then require the returned function contains them.
    If `Or` contains an iterable then include any other tags that are specified.
    """
    containers = (builtins.tuple, builtins.set, builtins.list)
    boolean = {key : {item for item in value} if isinstance(value, containers) else {value} for key, value in boolean.items()}

    # Nothing specific was queried, so just yield all tagnames that are available.
    if not boolean:
        for ea, _ in sorted(internal.comment.contents.iterate()):
            if function.within(ui.navigation.procedure(ea)):
                contents, owners, Flogging = internal.comment.contents.name(ea, target=ea), {f for f in function.chunk.owners(ea)}, logging.info
            else:
                contents, owners, Flogging = [], {f for f in []}, logging.warning
            if contents and ea in owners: yield ea, contents
            elif ea not in owners: Flogging(u"{:s}.selectcontents() : Refusing to yield {:d} contents tag{:s} for {:s} ({:#x}) possibly due to cache inconsistency as it is not referencing {:s}.".format(__name__, len(contents), '' if len(contents) == 1 else 's', 'function address' if function.within(ea) else 'address', ea, "a candidate function address ({:s})".format(', '.join(map("{:#x}".format, owners)) if owners else 'a function')))
        return

    # Collect the tagnames to query as specified by the user.
    Or, And = ({item for item in boolean.get(B, [])} for B in ['Or', 'And'])

    # Walk through the index verifying that they're within a function. This
    # way we can cross-check their cache against the user's query.
    for ea, cache in sorted(internal.comment.contents.iterate()):
        if function.within(ui.navigation.procedure(ea)):
            sup, contents = {key for key in cache}, internal.comment.contents._read(ea, ea) or {}

        # Otherwise if we're not within a function then our cache is lying to us
        # and we need to skip this iteration.
        else:
            q = utils.string.kwargs(boolean)
            logging.warning(u"{:s}.selectcontents({:s}) : Detected cache inconsistency where address ({:#x}) should be referencing a function.".format(__name__, q, ea))
            continue

        # Check to see that the global contents cache (supval) matches the actual
        # function contents cache (blob). This isn't too serious because we always
        # trust the real function cache, but it implies that there was an
        # inconsistency when the global index of written tagnames was updated.
        blob = {key for key in contents}
        if blob != sup:
            f, q = function.address(ea), utils.string.kwargs(boolean)
            sup_formatted, blob_formatted = (', '.join(items) for items in [sup, blob])
            logging.warning(u"{:s}.selectcontents({:s}) : Detected cache inconsistency between contents of {:s} address ({:#x}) and address ({:#x}) due to a difference between the supval ({:s}) and its corresponding blob ({:s}).".format(__name__, q, f, 'function', ea, sup_formatted, blob_formatted))

        # Now start aggregating the tagnames that the user is searching for.
        collected, names, owners = {item for item in []}, internal.comment.contents.name(ea, target=ea), {item for item in function.chunk.owners(ea)}

        # Or(|) includes the address if any of the tagnames matched.
        collected.update(Or & names)

        # And(&) includes tags only if the address includes all of the specified tagnames.
        if And:
            if And & names == And:
                collected.update(And)
            else: continue

        # If anything was collected (tagnames were matched), then yield the
        # address along with the matching tagnames.
        if collected and ea in owners: yield ea, collected
        elif ea not in owners: logging.info(u"{:s}.selectcontents({:s}) : Refusing to select from {:d} contents tag{:s} for {:s} address ({:#x}) possibly due to cache inconsistency as it is not referencing {:s}.".format(__name__, utils.string.kwargs(boolean), len(names), '' if len(names) == 1 else 's', 'function', ea, "a candidate function address ({:s})".format(', '.join(map("{:#x}".format, owners)) if owners else 'a function')))
    return
selectcontent = utils.alias(selectcontents)

## imports
class imports(object):
    """
    This namespace is used for listing all of the imports within the
    database. Each import is represented by an address along with any
    naming information that is required to dynamically link external
    symbols with the binary.

    By default a tuple is yielded for each import with the format
    `(address, (shared-object, name, hint))`. In this tuple,
    `shared-object` represents the name of the shared object the
    import is imported from. The `name` is the symbol name to link
    with, and `hint` is the import ordinal hint which is used to speed
    up the linking process.

    When listing the imports that are matched, the following legend can be
    used to identify certain characteristics about them:

        `T` - The import has a type that was explicitly applied
        `t` - The import has a type that was guessted
        `H` - The import contains an ordinal number as a hint
        `+` - The import has an implicit tag applied to it (named or typed)
        `*` - The import has an explicit tag applied to it

    The different types that one can match imports with are the following:

        `address` or `ea` - Match according to the import's address
        `name` - Match according to the import's symbol name
        `module` - Filter the imports according to the specified module name
        `fullname` - Match according to the full symbol name (module + symbol)
        `like` - Filter the symbol names of all the imports according to a glob
        `regex` - Filter the symbol names of all the imports according to a regular-expression
        `ordinal` - Match according to the import's hint (ordinal)
        `index` - Match according index of the import
        `typed` - Filter all of the imports based on whether they have a type applied to them
        `tagged` - Filter the imports for any that use the specified tag(s)
        `predicate` Filter the imports by passing the above (default) tuple to a callable

    Some examples of using these keywords are as follows::

        > database.imports.list(module='kernelbase.dll')
        > iterable = database.imports.iterate(like='*alloc*')
        > result = database.imports.search(index=42)

    """
    def __new__(cls):
        return cls.__iterate__()

    @staticmethod
    def __symbol__(module_name_ordinal):
        module, name, ordinal = module_name_ordinal

        # FIXME: I believe this is a windows-only scheme...
        name = name or u"Ordinal{:d}".format(ordinal)

        # FIXME: I think this is a gnu-only thing...
        if module is None and '@@' in name:
            nestname, nestmodule = name.rsplit('@@', 1)
            return utils.string.of(nestmodule), utils.string.of(nestname)
        return utils.string.of(module), utils.string.of(name)

    @staticmethod
    def __formats__(module_name_ordinal):
        _, name = imports.__symbol__(module_name_ordinal)
        return name
    @staticmethod
    def __formatl__(module_name_ordinal):
        module, name = imports.__symbol__(module_name_ordinal)
        # FIXME: use "`" instead of "!" when analyzing an OSX fat binary
        return u"{:s}!{:s}".format(module, name)

    __format__ = __formatl__

    __matcher__ = utils.matcher()
    __matcher__.mapping('address', operator.itemgetter(0)), __matcher__.mapping('ea', operator.itemgetter(0))
    __matcher__.boolean('name', lambda name, item: name.lower() == item.lower(), operator.itemgetter(1), __formats__.__func__)
    __matcher__.combinator('fullname', utils.fcompose(fnmatch.translate, utils.fpartial(re.compile, flags=re.IGNORECASE), operator.attrgetter('match')), operator.itemgetter(1), __formatl__.__func__)
    __matcher__.combinator('like', utils.fcompose(fnmatch.translate, utils.fpartial(re.compile, flags=re.IGNORECASE), operator.attrgetter('match')), operator.itemgetter(1), __formats__.__func__)
    __matcher__.combinator('module', utils.fcompose(fnmatch.translate, utils.fpartial(re.compile, flags=re.IGNORECASE), operator.attrgetter('match')), operator.itemgetter(1), operator.itemgetter(0))
    __matcher__.mapping('ordinal', utils.fcompose(operator.itemgetter(1), operator.itemgetter(-1)))
    __matcher__.combinator('regex', utils.fcompose(utils.fpartial(re.compile, flags=re.IGNORECASE), operator.attrgetter('match')), operator.itemgetter(1), __format__.__func__)
    __matcher__.mapping('typed', operator.truth, operator.itemgetter(0), lambda ea: idaapi.get_tinfo2(ea, idaapi.tinfo_t()) if idaapi.__version__ < 7.0 else idaapi.get_tinfo(idaapi.tinfo_t(), ea))
    __matcher__.boolean('tagged', lambda parameter, keys: operator.truth(keys) == parameter if isinstance(parameter, bool) else operator.contains(keys, parameter) if isinstance(parameter, six.string_types) else keys&parameter, tag, operator.methodcaller('keys'), builtins.set)
    __matcher__.predicate('predicate', lambda item: item)
    __matcher__.predicate('pred', lambda item: item)
    __matcher__.mapping('index', operator.itemgetter(0))

    @classmethod
    def __iterate__(cls):
        """Iterate through all of the imports in the database.

        Yields `(address, (module, name, ordinal))` for each iteration.
        """
        for idx in builtins.range(idaapi.get_import_module_qty()):
            module = idaapi.get_import_module_name(idx)
            listable = []
            idaapi.enum_import_names(idx, utils.fcompose(lambda *items: items, listable.append, utils.fconstant(True)))
            for ea, name, ordinal in listable:
                ui.navigation.set(ea)
                realmodule, realname = cls.__symbol__((module, name, ordinal))
                yield ea, (utils.string.of(realmodule), utils.string.of(realname), ordinal)
            continue
        return

    @utils.multicase(string=six.string_types)
    @classmethod
    @utils.string.decorate_arguments('string')
    def iterate(cls, string):
        '''Iterate through all of the imports in the database with a glob that matches `string`.'''
        return cls.iterate(like=string)
    @utils.multicase()
    @classmethod
    @utils.string.decorate_arguments('name', 'module', 'fullname', 'like', 'regex')
    def iterate(cls, **type):
        '''Iterate through all of the imports in the database that match the keyword specified by `type`.'''
        iterable = cls.__iterate__()
        for key, value in (type or {'predicate': utils.fconstant(True)}).items():
            iterable = (item for item in cls.__matcher__.match(key, value, iterable))
        for item in iterable: yield item

    # searching
    @utils.multicase()
    @classmethod
    def at(cls):
        '''Return the import at the current address.'''
        return cls.at(ui.current.address())
    @utils.multicase(ea=six.integer_types)
    @classmethod
    def at(cls, ea):
        '''Return the import at the address `ea`.'''
        ea = interface.address.inside(ea)
        Fcrit = utils.fcompose(operator.itemgetter(0), functools.partial(operator.eq, ea))
        iterable = (item for item in cls.__iterate__() if Fcrit(item))
        try:
            _, item = builtins.next(iterable)
            return item
        except StopIteration:
            pass
        raise E.MissingTypeOrAttribute(u"{:s}.at({:#x}) : Unable to determine import at specified address.".format('.'.join([__name__, cls.__name__]), ea))

    @utils.multicase()
    @classmethod
    def module(cls):
        '''Return the import module at the current address.'''
        return cls.module(ui.current.address())
    @utils.multicase(ea=six.integer_types)
    @classmethod
    def module(cls, ea):
        '''Return the import module at the specified address `ea`.'''
        ea = interface.address.inside(ea)
        for addr, (module, _, _) in cls.__iterate__():
            if addr == ea:
                return module
            continue
        raise E.MissingTypeOrAttribute(u"{:s}.module({:#x}) : Unable to determine import module name at specified address.".format('.'.join([__name__, cls.__name__]), ea))

    # specific parts of the import
    @utils.multicase()
    @classmethod
    def fullname(cls):
        '''Return the full name of the import at the current address.'''
        return cls.fullname(ui.current.address())
    @utils.multicase()
    @classmethod
    def fullname(cls, ea):
        '''Return the full name of the import at address `ea`.'''
        return cls.__formatl__(cls.at(ea))

    @utils.multicase()
    @classmethod
    def name(cls):
        '''Return the name of the import at the current address.'''
        return cls.name(ui.current.address())
    @utils.multicase()
    @classmethod
    def name(cls, ea):
        '''Return the name of the import at address `ea`.'''
        return cls.__formats__(cls.at(ea))

    @utils.multicase()
    @classmethod
    def ordinal(cls):
        '''Return the ordinal of the import at the current address.'''
        return cls.ordinal(ui.current.address())
    @utils.multicase()
    @classmethod
    def ordinal(cls, ea):
        '''Return the ordinal of the import at the address `ea`.'''
        _, _, ordinal = cls.at(ea)
        return ordinal

    # FIXME: maybe implement a modules class for getting information on import modules
    @classmethod
    def modules(cls):
        '''Return all of the import modules defined in the database.'''
        iterable = (module for _, (module, _, _) in cls.__iterate__())
        settable = {item for item in iterable if item}
        return [utils.string.of(item) for item in settable]

    @utils.multicase(string=six.string_types)
    @classmethod
    @utils.string.decorate_arguments('string')
    def list(cls, string):
        '''List all of the imports matching the glob `string` against the fullname.'''
        return cls.list(fullname=string)
    @utils.multicase()
    @classmethod
    @utils.string.decorate_arguments('name', 'module', 'fullname', 'like', 'regex')
    def list(cls, **type):
        '''List all of the imports in the database that match the keyword specified by `type`.'''
        MANGLED_CODE, MANGLED_DATA, MANGLED_UNKNOWN = getattr(idaapi, 'MANGLED_CODE', 0), getattr(idaapi, 'MANGLED_DATA', 1), getattr(idaapi, 'MANGLED_UNKNOWN', 2)
        Fmangled_type = idaapi.get_mangled_name_type if hasattr(idaapi, 'get_mangled_name_type') else utils.fcompose(utils.frpartial(idaapi.demangle_name, 0), utils.fcondition(operator.truth)(MANGLED_DATA, MANGLED_UNKNOWN))
        MNG_NODEFINIT, MNG_NOPTRTYP, MNG_LONG_FORM = getattr(idaapi, 'MNG_NODEFINIT', 8), getattr(idaapi, 'MNG_NOPTRTYP', 7), getattr(idaapi, 'MNG_LONG_FORM', 0x6400007)

        # Set some reasonable defaults
        maxaddr = maxmodule = cordinal = maxname = 0
        has_ordinal = False

        # Perform the first pass through our listable grabbing our field lengths
        listable = []
        for ea, (module, name, ordinal) in cls.iterate(**type):
            maxaddr = max(ea, maxaddr)
            maxname = max(len(name or ''), maxname)

            # Figure out the module with the longest name and store its length
            # whilst including the ordinal length.
            if len(module or '') > maxmodule:
                maxmodule, cordinal = len(module or ''), len("<{:d}>".format(ordinal))
            has_ordinal = has_ordinal or ordinal > 0

            # Save the item we just iterated through so we don't have to go
            # through it again.
            listable.append((ea, (module, name, ordinal)))

        # Collect the number of digits for the maximum address extracted from the first pass
        caddr = utils.string.digits(maxaddr, 16)

        # List all the fields of every import that was matched
        prefix, get_tinfo = '__imp_', (lambda ti, ea: idaapi.get_tinfo2(ea, ti)) if idaapi.__version__ < 7.0 else idaapi.get_tinfo
        for ea, (module, name, ordinal) in listable:
            ui.navigation.set(ea)
            moduleordinal = "{:s}<{:d}>".format(module or '', ordinal) if ordinal else (module or '')

            address_s = "{:<#0{:d}x}".format(ea, 2 + math.trunc(caddr))
            module_s = "{:>{:d}s}".format(moduleordinal if module else '', maxmodule + (2 + cordinal if has_ordinal else 0))

            # Clean up the the name and then figure out what the actual name would be. We first
            # strip out the import prefix, then figure out the type before we render just the name.
            name = name[len(prefix):] if name.startswith(prefix) else name
            mangled_name_type_t = Fmangled_type(utils.string.to(name))
            realname = name if mangled_name_type_t == MANGLED_UNKNOWN else utils.string.of(idaapi.demangle_name(utils.string.to(name), MNG_NODEFINIT|MNG_NOPTRTYP) or name)

            # Some flags that are probably useful.
            ftyped = 'T' if get_tinfo(idaapi.tinfo_t(), ea) else 't' if t.has_typeinfo(ea) else '-'
            fordinaled = 'H' if ordinal > 0 else '-'

            tags = tag(ea)
            tags.pop('__name__', None)
            ftagged = '-' if not tags else '*' if any(not item.startswith('__') for item in tags) else '+'

            flags = itertools.chain(ftyped, fordinaled, ftagged)

            # If there's any type information for the address, then we can just render it.
            ti = idaapi.tinfo_t()
            if get_tinfo(ti, ea):
                description = idaapi.print_tinfo('', 0, 0, idaapi.PRTYPE_DEF, ti, utils.string.to(realname), '')
                six.print_(u"{:s} : {:s} : {:s} : {:s}".format(address_s, ''.join(flags), module_s, utils.string.of(description)))

            # Otherwise we'll use the realname to demangle it to something displayable.
            else:
                description = idaapi.demangle_name(utils.string.to(name), MNG_LONG_FORM) or realname
                six.print_(u"{:s} : {:s} : {:s} : {:s}".format(address_s, ''.join(flags), module_s, utils.string.of(description)))
            continue
        return

    @utils.multicase(string=six.string_types)
    @classmethod
    @utils.string.decorate_arguments('string')
    def search(cls, string):
        '''Search through all of the imports matching the fullname glob `string`.'''
        return cls.search(fullname=string)
    @utils.multicase()
    @classmethod
    @utils.string.decorate_arguments('name', 'module', 'fullname', 'like', 'regex')
    def search(cls, **type):
        '''Search through all of the imports within the database and return the first result matching the keyword specified by `type`.'''
        query_s = utils.string.kwargs(type)

        listable = [item for item in cls.iterate(**type)]
        if len(listable) > 1:
            messages = (u"{:x} {:s}{:s} {:s}".format(ea, module, "<{:d}>".format(ordinal) if ordinal else '', name) for ea, (module, name, ordinal) in listable)
            [ logging.info(msg) for msg in messages ]
            f = utils.fcompose(operator.itemgetter(1), cls.__formatl__)
            logging.warning(u"{:s}.search({:s}) : Found {:d} matching results. Returning the first import \"{:s}\".".format('.'.join([__name__, cls.__name__]), query_s, len(listable), utils.string.escape(f(listable[0]), '"')))

        iterable = (item for item in listable)
        res = builtins.next(iterable, None)
        if res is None:
            raise E.SearchResultsError(u"{:s}.search({:s}) : Found 0 matching results.".format('.'.join([__name__, cls.__name__]), query_s))
        return res[0]

###
class address(object):
    """
    This namespace is used for translating an address in the database
    to another address according to a number of constraints or types.
    Essentially these functions are used to assist with navigation.
    As an example, these functions allow one to navigate between the
    next and previous "call" instructions, addresses that contain
    data references, or even to navigate to unknown (undefined)
    addresses.

    This namespace is also aliased as ``database.a``.

    Some of the more common functions are used so often that they're also
    aliased as globals. Each of these can be used for navigation or for
    determining the next valid address. These are:

        ``database.next`` - Return the "next" defined address
        ``database.prev`` - Return the "previous" defined address
        ``database.nextref`` - Return the "next" address with a reference.
        ``database.prevref`` - Return the "previous" address with a reference
        ``database.nextreg`` - Return the "next" address using a register
        ``database.prevreg`` - Return the "previous" address using a register

    Some examples of using this namespace can be::

        > ea = database.a.next(ea)
        > ea = database.a.prevreg(ea, 'edx', write=1)
        > ea = database.a.nextref(ea)
        > ea = database.a.prevcall(ea)

    """

    # FIXME
    # The methods in this namespace should be put into a utils class. This way
    # each of these operations can be exposed to the user in function.chunks,
    # function.block, etc. Most of these functions only need to know their
    # searching boundaries, and so we should derive from that logic for our class.

    @utils.multicase()
    def __new__(cls):
        '''Return the current address or a list of addresses for the current selection.'''
        address, selection = ui.current.address(), ui.current.selection()
        if operator.eq(*(internal.interface.address.head(ea, silent=True) for ea in selection)):
            return cls.head(address)
        start, stop = selection
        return [ea for ea in cls.iterate(start, stop)]
    @utils.multicase(ea=six.integer_types)
    def __new__(cls, ea):
        '''Return the address of the item containing the address `ea`.'''
        return cls.head(ea)
    @utils.multicase(start=six.integer_types, end=six.integer_types)
    def __new__(cls, start, end):
        '''Return a list containing each of the addresses from `start` to `end`.'''
        return [ea for ea in cls.iterate(start, end)]
    @utils.multicase(start=six.integer_types, end=six.integer_types, step=callable)
    def __new__(cls, start, end, step):
        '''Return a list containing each of the addresses from `start` to `end` using the callable `step` to determine the next address.'''
        return [ea for ea in cls.iterate(start, end, step)]
    @utils.multicase(bounds=tuple)
    def __new__(cls, bounds):
        '''Return a list containing each of the addresses within `bounds`.'''
        return [ea for ea in cls.iterate(bounds)]
    @utils.multicase(bounds=tuple, step=callable)
    def __new__(cls, bounds, step):
        '''Return a list containing each of the addresses within `bounds` using the callable `step` to determine the next address.'''
        return [ea for ea in cls.iterate(bounds, step)]

    @utils.multicase()
    @classmethod
    def bounds(cls):
        '''Return the bounds of the current address or selection in a tuple formatted as `(left, right)`.'''
        address, selection = ui.current.address(), ui.current.selection()
        if operator.eq(*(internal.interface.address.head(ea, silent=True) for ea in selection)):
            return cls.bounds(address)
        start, stop = selection
        return interface.bounds_t(start, cls.next(stop))
    @utils.multicase(ea=six.integer_types)
    @classmethod
    def bounds(cls, ea):
        '''Return the bounds of the specified address `ea` in a tuple formatted as `(left, right)`.'''
        return interface.bounds_t(ea, ea + type.size(ea))

    @staticmethod
    def __walk__(ea, next, match):
        '''Return the first address from `ea` using `next` for stepping until the provided callable doesn't `match`.'''
        res = interface.address.inside(ea)

        # Now that we know we're a valid address in the database,
        # we simply need to keeping calling next() while match()
        # continuously allows us to.
        while res not in {None, idaapi.BADADDR} and match(res):
            ea = ui.navigation.analyze(res)
            res = next(ea)
        return res

    @utils.multicase()
    @classmethod
    def iterate(cls):
        '''Iterate through the currently selected addresses.'''
        selection = ui.current.selection()
        return cls.iterate(selection)
    @utils.multicase(end=six.integer_types)
    @classmethod
    def iterate(cls, end):
        '''Iterate from the current address to `end`.'''
        return cls.iterate(ui.current.address(), end)
    @utils.multicase(end=six.integer_types, step=callable)
    @classmethod
    def iterate(cls, end, step):
        '''Iterate from the current address to `end` using the callable `step` to determine the next address.'''
        return cls.iterate(ui.current.address(), end, step)
    @utils.multicase(start=six.integer_types, end=six.integer_types)
    @classmethod
    def iterate(cls, start, end):
        '''Iterate from address `start` to `end`.'''
        start, end = interface.address.within(start, end)
        step = cls.prev if start > end else cls.next
        return cls.iterate(start, end, step)
    @utils.multicase(start=six.integer_types, end=six.integer_types, step=callable)
    @classmethod
    def iterate(cls, start, end, step):
        '''Iterate from address `start` to `end` using the callable `step` to determine the next address.'''
        left, right = config.bounds()

        # we need to always ensure that the maximum address is always excluded. no
        # good reason for this, but i'm pretty sure that this is how this had always
        # worked as the positions we get should be thought of like a cursor.
        op = operator.lt if start <= end else operator.ge
        ea, stop = interface.address.within(start, end) if start <= end else reversed(sorted(interface.address.inside(end, start - 1)))

        # loop continuosly until we terminate or we run out of bounds.
        try:
            while ea not in {idaapi.BADADDR, None} and op(ea, stop):
                yield ea
                ea = step(ea)
        except E.OutOfBoundsError:
            pass
        return
    @utils.multicase(bounds=tuple)
    @classmethod
    def iterate(cls, bounds):
        '''Iterate through all of the addresses defined within `bounds`.'''
        left, right = bounds
        return cls.iterate(left, right, cls.prev if left > right else cls.next)
    @utils.multicase(bounds=tuple, step=callable)
    @classmethod
    def iterate(cls, bounds, step):
        '''Iterate through all of the addresses defined within `bounds` using the callable `step` to determine the next address.'''
        left, right = bounds
        return cls.iterate(left, right, step)

    @utils.multicase()
    @classmethod
    def blocks(cls):
        '''Iterate through the currently selected blocks.'''
        selection = ui.current.selection()
        return cls.blocks(selection)
    @utils.multicase(end=six.integer_types)
    @classmethod
    def blocks(cls, end):
        '''Yields the boundaries of each block from the current address to `end`.'''
        return cls.blocks(ui.current.address(), end)
    @utils.multicase(bounds=tuple)
    @classmethod
    def blocks(cls, bounds):
        '''Yields the boundaries of each block within the specified `bounds`.'''
        left, right = bounds
        return cls.blocks(left, right)
    @utils.multicase(start=six.integer_types, end=six.integer_types)
    @classmethod
    def blocks(cls, start, end):
        '''Yields the boundaries of each block between the addresses `start` and `end`.'''
        block, _ = start, end = interface.address.head(start), address.tail(end) + 1
        for ea in cls.iterate(start, end):
            nextea = cls.next(ea)

            ## XXX: it seems that idaapi.is_basic_block_end requires the following to be called
            # idaapi.decode_insn(insn, ea)
            ## XXX: for some reason is_basic_block_end will occasionally include some stray 'call' instructions
            # if idaapi.is_basic_block_end(ea):
            #     yield block, nextea
            ## XXX: in later versions of ida, is_basic_block_end takes two args (ea, bool call_insn_stops_block)

            # skip call instructions
            if _instruction.type.is_call(ea):
                continue

            # halting instructions terminate a block
            if _instruction.type.is_return(ea):
                yield interface.bounds_t(block, nextea)
                block = ea

            # branch instructions will terminate a block
            elif cxdown(ea):
                yield interface.bounds_t(block, nextea)
                block = nextea

            # a branch target will also terminate a block
            elif cxup(ea) and block != ea:
                yield interface.bounds_t(block, ea)
                block = ea
            continue
        return

    @utils.multicase()
    @classmethod
    def head(cls):
        '''Return the address of the byte at the beginning of the current address.'''
        return cls.head(ui.current.address())
    @utils.multicase(ea=six.integer_types)
    @classmethod
    def head(cls, ea):
        '''Return the address of the byte at the beginning of the address `ea`.'''
        ea = interface.address.within(ea)
        return idaapi.get_item_head(ea)

    @utils.multicase()
    @classmethod
    def tail(cls):
        '''Return the last byte at the end of the current address.'''
        return cls.tail(ui.current.address())
    @utils.multicase(ea=six.integer_types)
    @classmethod
    def tail(cls, ea):
        '''Return the address of the last byte at the end of the address at `ea`.'''
        ea = interface.address.within(ea)
        return idaapi.get_item_end(ea) - 1

    @utils.multicase()
    @classmethod
    def prev(cls, **count):
        '''Return the previous address from the current address.'''
        return cls.prev(ui.current.address(), count.pop('count', 1))
    @utils.multicase(predicate=builtins.callable)
    @classmethod
    def prev(cls, predicate, **count):
        '''Return the previous address from the current address that satisfies the provided `predicate`.'''
        return cls.prev(ui.current.address(), predicate, **count)
    @utils.multicase(ea=six.integer_types)
    @classmethod
    def prev(cls, ea):
        '''Return the previous address from the address specified by `ea`.'''
        return cls.prev(ea, 1)
    @utils.multicase(ea=six.integer_types, predicate=builtins.callable)
    @classmethod
    def prev(cls, ea, predicate):
        '''Return the previous address from the address `ea` that satisfies the provided `predicate`.'''
        return cls.prevF(ea, predicate, 1)
    @utils.multicase(ea=six.integer_types, count=six.integer_types)
    @classmethod
    def prev(cls, ea, count):
        '''Return the previous `count` addresses from the address specified by `ea`.'''
        return cls.prevF(ea, utils.fidentity, count)
    @utils.multicase(ea=six.integer_types, predicate=builtins.callable, count=six.integer_types)
    @classmethod
    def prev(cls, ea, predicate, count):
        '''Return the previous `count` addresses from the address `ea` that satisfies the provided `predicate`.'''
        return cls.prevF(ea, predicate, count)

    @utils.multicase()
    @classmethod
    def next(cls, **count):
        '''Return the next address from the current address.'''
        return cls.next(ui.current.address(), count.pop('count', 1))
    @utils.multicase(predicate=builtins.callable)
    @classmethod
    def next(cls, predicate, **count):
        '''Return the next address from the current address that satisfies the provided `predicate`.'''
        return cls.next(ui.current.address(), predicate, **count)
    @utils.multicase(ea=six.integer_types)
    @classmethod
    def next(cls, ea):
        '''Return the next address from the address `ea`.'''
        return cls.next(ea, 1)
    @utils.multicase(ea=six.integer_types, predicate=builtins.callable)
    @classmethod
    def next(cls, ea, predicate):
        '''Return the next address from the address `ea` that satisfies the provided `predicate`.'''
        return cls.nextF(ea, predicate, 1)
    @utils.multicase(ea=six.integer_types, count=six.integer_types)
    @classmethod
    def next(cls, ea, count):
        '''Return the next `count` addresses from the address specified by `ea`.'''
        return cls.nextF(ea, utils.fidentity, count)
    @utils.multicase(ea=six.integer_types, predicate=builtins.callable, count=six.integer_types)
    @classmethod
    def next(cls, ea, predicate, count):
        '''Return the next `count` addresses from the address `ea` that satisfies the provided `predicate`.'''
        return cls.nextF(ea, predicate, count)

    @utils.multicase(predicate=builtins.callable)
    @classmethod
    def prevF(cls, predicate, **count):
        '''Return the previous address from the current one that satisfies the provided `predicate`.'''
        return cls.prevF(ui.current.address(), predicate, count.pop('count', 1))
    @utils.multicase(ea=six.integer_types, predicate=builtins.callable)
    @classmethod
    def prevF(cls, ea, predicate, **count):
        '''Return the previous address from the address `ea` that satisfies the provided `predicate`.'''
        return cls.prevF(ea, predicate, count.pop('count', 1))
    @utils.multicase(ea=six.integer_types, predicate=builtins.callable, count=six.integer_types)
    @classmethod
    def prevF(cls, ea, predicate, count):
        '''Return the previous `count` addresses from the address `ea` that satisfies the provided `predicate`.'''
        Fprev, Finverse = utils.fcompose(interface.address.within, idaapi.prev_not_tail), utils.fcompose(predicate, operator.not_)

        # If we're at the very bottom address of the database then skip
        # the boundary check for interface.address.within().
        _, bottom = config.bounds()
        if ea == bottom:
            Fprev = idaapi.prev_not_tail

        # Otherwise if we're already at the top, there's nowhere else to go.
        if Fprev(ea) == idaapi.BADADDR:
            raise E.AddressOutOfBoundsError(u"{:s}.prevF: Refusing to seek past the top of the database ({:#x}). Stopped at address {:#x}.".format('.'.join([__name__, cls.__name__]), config.bounds()[0], ea))

        # Walk until right before the matching address, and then return the one before.
        res = cls.__walk__(Fprev(ea), Fprev, Finverse)
        return cls.prevF(res, predicate, count - 1) if count > 1 else res

    @utils.multicase(predicate=builtins.callable)
    @classmethod
    def nextF(cls, predicate, **count):
        '''Return the next address from the current one that satisfies the provided `predicate`.'''
        return cls.nextF(ui.current.address(), predicate, count.pop('count', 1))
    @utils.multicase(ea=six.integer_types, predicate=builtins.callable)
    @classmethod
    def nextF(cls, ea, predicate, **count):
        '''Return the next address from the address `ea` that satisfies the provided `predicate`.'''
        return cls.nextF(ea, predicate, count.pop('count', 1))
    @utils.multicase(ea=six.integer_types, predicate=builtins.callable, count=six.integer_types)
    @classmethod
    def nextF(cls, ea, predicate, count):
        '''Return the next `count` addresses from the address `ea` that satisfies the provided `predicate`.'''
        Fnext, Finverse = utils.fcompose(interface.address.within, idaapi.next_not_tail), utils.fcompose(predicate, operator.not_)

        # If we're at the very bottom of the database, then we're done.
        if Fnext(ea) == idaapi.BADADDR:
            raise E.AddressOutOfBoundsError(u"{:s}.nextF: Refusing to seek past the bottom of the database ({:#x}). Stopped at address {:#x}.".format('.'.join([__name__, cls.__name__]), config.bounds()[1], idaapi.get_item_end(ea)))

        # Walk until right before the matching address, and then return the one after.
        res = cls.__walk__(Fnext(ea), Fnext, Finverse)
        return cls.nextF(res, predicate, count - 1) if count > 1 else res

    @utils.multicase()
    @classmethod
    def prevref(cls, **count):
        '''Return the previous address from the current one that has anything referencing it.'''
        return cls.prevref(ui.current.address(), count.pop('count', 1))
    @utils.multicase(predicate=builtins.callable)
    @classmethod
    def prevref(cls, predicate, **count):
        '''Return the previous address from the current one that has anything referencing it and satisfies the provided `predicate`.'''
        return cls.prevref(ui.current.address(), predicate, **count)
    @utils.multicase(ea=six.integer_types)
    @classmethod
    def prevref(cls, ea):
        '''Return the previous address from the address `ea` that has anything referencing it.'''
        return cls.prevref(ea, 1)
    @utils.multicase(ea=six.integer_types, predicate=builtins.callable)
    @classmethod
    def prevref(cls, ea, predicate, **count):
        '''Return the previous address from the address `ea` that has anything referencing it and satisfies the provided `predicate`.'''
        Fxref = utils.fcompose(xref.up, len, functools.partial(operator.lt, 0))
        F = utils.fcompose(utils.fmap(Fxref, predicate), builtins.all)
        return cls.prevF(ea, F, count.pop('count', 1))
    @utils.multicase(ea=six.integer_types, count=six.integer_types)
    @classmethod
    def prevref(cls, ea, count):
        '''Return the previous `count` addresses from the address `ea` that has anything referencing it.'''
        Fxref = utils.fcompose(xref.up, len, functools.partial(operator.lt, 0))
        return cls.prevF(ea, Fxref, count)

    @utils.multicase()
    @classmethod
    def nextref(cls, **count):
        '''Return the next address from the current one that has anything referencing it.'''
        return cls.nextref(ui.current.address(), count.pop('count', 1))
    @utils.multicase(predicate=builtins.callable)
    @classmethod
    def nextref(cls, predicate, **count):
        '''Return the next address from the current one that has anything referencing it and satisfies the provided `predicate`.'''
        return cls.nextref(ui.current.address(), predicate, **count)
    @utils.multicase(ea=six.integer_types)
    @classmethod
    def nextref(cls, ea):
        '''Return the next address from the address `ea` that has anything referencing it.'''
        return cls.nextref(ea, 1)
    @utils.multicase(ea=six.integer_types, predicate=builtins.callable)
    @classmethod
    def nextref(cls, ea, predicate, **count):
        '''Return the next address from the address `ea` that has anything referencing it and satisfies the provided `predicate`.'''
        Fxref = utils.fcompose(xref.up, len, functools.partial(operator.lt, 0))
        F = utils.fcompose(utils.fmap(Fxref, predicate), builtins.all)
        return cls.nextF(ea, Fxref, count.pop('count', 1))
    @utils.multicase(ea=six.integer_types, count=six.integer_types)
    @classmethod
    def nextref(cls, ea, count):
        '''Return the next `count` addresses from the address `ea` that has anything referencing it.'''
        Fxref = utils.fcompose(xref.up, len, functools.partial(operator.lt, 0))
        return cls.nextF(ea, Fxref, count)

    @utils.multicase()
    @classmethod
    def prevdref(cls, **count):
        '''Return the previous address from the current one that has data referencing it.'''
        return cls.prevdref(ui.current.address(), count.pop('count', 1))
    @utils.multicase(predicate=builtins.callable)
    @classmethod
    def prevdref(cls, predicate, **count):
        '''Return the previous address from the current one that has data referencing it and satisfies the provided `predicate`.'''
        return cls.prevdref(ui.current.address(), predicate, **count)
    @utils.multicase(ea=six.integer_types)
    @classmethod
    def prevdref(cls, ea):
        '''Return the previous address from the address `ea` that has data referencing it.'''
        return cls.prevdref(ea, 1)
    @utils.multicase(ea=six.integer_types, predicate=builtins.callable)
    @classmethod
    def prevdref(cls, ea, predicate, **count):
        '''Return the previous address from the address `ea` that has data referencing it and satisfies the provided `predicate`.'''
        Fdref = utils.fcompose(xref.data_up, len, functools.partial(operator.lt, 0))
        F = utils.fcompose(utils.fmap(Fdref, predicate), builtins.all)
        return cls.prevF(ea, F, count.pop('count', 1))
    @utils.multicase(ea=six.integer_types, count=six.integer_types)
    @classmethod
    def prevdref(cls, ea, count):
        '''Return the previous `count` addresses from the address `ea` that has data referencing it.'''
        Fdref = utils.fcompose(xref.data_up, len, functools.partial(operator.lt, 0))
        return cls.prevF(ea, Fdref, count)

    @utils.multicase()
    @classmethod
    def nextdref(cls, **count):
        '''Return the next address from the current one that has data referencing it.'''
        return cls.nextdref(ui.current.address(), count.pop('count', 1))
    @utils.multicase(predicate=builtins.callable)
    @classmethod
    def nextdref(cls, predicate, **count):
        '''Return the next address from the current one that has data referencing it and satisfies the provided `predicate`.'''
        return cls.nextdref(ui.current.address(), predicate, **count)
    @utils.multicase(ea=six.integer_types)
    @classmethod
    def nextdref(cls, ea):
        '''Return the next address from the address `ea` that has data referencing it.'''
        return cls.nextdref(ea, 1)
    @utils.multicase(ea=six.integer_types, predicate=builtins.callable)
    @classmethod
    def nextdref(cls, ea, predicate, **count):
        '''Return the next address from the address `ea` that has data referencing it and satisfies the provided `predicate`.'''
        Fdref = utils.fcompose(xref.data_up, len, functools.partial(operator.lt, 0))
        F = utils.fcompose(utils.fmap(Fdref, predicate), builtins.all)
        return cls.nextF(ea, F, count.pop('count', 1))
    @utils.multicase(ea=six.integer_types, count=six.integer_types)
    @classmethod
    def nextdref(cls, ea, count):
        '''Return the next `count` addresses from the address `ea` that has data referencing it.'''
        Fdref = utils.fcompose(xref.data_up, len, functools.partial(operator.lt, 0))
        return cls.nextF(ea, Fdref, count)

    # FIXME: the semantics of these aliases are wrong, and they really shouldn't be
    #        aliasing a data reference. thus, we should be checking the address' type.
    prevdata, nextdata = utils.alias(prevdref, 'address'), utils.alias(nextdref, 'address')

    @utils.multicase()
    @classmethod
    def prevcref(cls, **count):
        '''Return the previous address from the current one that has code referencing it.'''
        return cls.prevcref(ui.current.address(), count.pop('count', 1))
    @utils.multicase(predicate=builtins.callable)
    @classmethod
    def prevcref(cls, predicate, **count):
        '''Return the previous address from the current one that has code referencing it and satisfies the provided `predicate`.'''
        return cls.prevcref(ui.current.address(), predicate, **count)
    @utils.multicase(ea=six.integer_types)
    @classmethod
    def prevcref(cls, ea):
        '''Return the previous address from the address `ea` that has code referencing it.'''
        return cls.prevcref(ea, 1)
    @utils.multicase(ea=six.integer_types, predicate=builtins.callable)
    @classmethod
    def prevcref(cls, ea, predicate, **count):
        '''Return the previous address from the address `ea` that has code referencing it and satisfies the provided `predicate`.'''
        Fcref = utils.fcompose(xref.code_up, len, functools.partial(operator.lt, 0))
        F = utils.fcompose(utils.fmap(Fcref, predicate), builtins.all)
        return cls.prevF(ea, Fcref, count.pop('count', 1))
    @utils.multicase(ea=six.integer_types, count=six.integer_types)
    @classmethod
    def prevcref(cls, ea, count):
        '''Return the previous `count` addresses from the address `ea` that has code referencing it.'''
        Fcref = utils.fcompose(xref.code_up, len, functools.partial(operator.lt, 0))
        return cls.prevF(ea, Fcref, count)

    @utils.multicase()
    @classmethod
    def nextcref(cls, **count):
        '''Return the next address from the current one that has code referencing it.'''
        return cls.nextcref(ui.current.address(), count.pop('count', 1))
    @utils.multicase(predicate=builtins.callable)
    @classmethod
    def nextcref(cls, predicate, **count):
        '''Return the next address from the current one that has code referencing it and satisfies the provided `predicate`.'''
        return cls.nextcref(ui.current.address(), predicate, **count)
    @utils.multicase(ea=six.integer_types)
    @classmethod
    def nextcref(cls, ea):
        '''Return the next address from the address `ea` that has code referencing it.'''
        return cls.nextcref(ea, 1)
    @utils.multicase(ea=six.integer_types, predicate=builtins.callable)
    @classmethod
    def nextcref(cls, ea, predicate, **count):
        '''Return the next address from the address `ea` that has code referencing it and satisfies the provided `predicate`.'''
        Fcref = utils.fcompose(xref.code_up, len, functools.partial(operator.lt, 0))
        F = utils.fcompose(utils.fmap(Fcref, predicate), builtins.all)
        return cls.nextF(ea, Fcref, count.pop('count', 1))
    @utils.multicase(ea=six.integer_types, count=six.integer_types)
    @classmethod
    def nextcref(cls, ea, count):
        '''Return the next `count` addresses from the address `ea` that has code referencing it.'''
        Fcref = utils.fcompose(xref.code_up, len, functools.partial(operator.lt, 0))
        return cls.nextF(ea, Fcref, count)

    # FIXME: the semantics of these aliases are wrong, and they really shouldn't be#
    #        aliasing a code reference. thus, we should be checking the address' type.
    prevcode, nextcode = utils.alias(prevcref, 'address'), utils.alias(nextcref, 'address')

    @utils.multicase(reg=(six.string_types, interface.register_t))
    @classmethod
    def prevreg(cls, reg, *regs, **modifiers):
        '''Return the previous address containing an instruction that uses `reg` or any one of the specified `regs`.'''
        return cls.prevreg(ui.current.address(), reg, *regs, **modifiers)
    @utils.multicase(predicate=builtins.callable, reg=(six.string_types, interface.register_t))
    @classmethod
    def prevreg(cls, predicate, reg, *regs, **modifiers):
        '''Return the previous address containing an instruction that uses `reg` or any one of the specified `regs` and satisfies the provided `predicate`.'''
        return cls.prevreg(ui.current.address(), predicate, reg, *regs, **modifiers)
    @utils.multicase(ea=six.integer_types, reg=(six.string_types, interface.register_t))
    @classmethod
    def prevreg(cls, ea, reg, *regs, **modifiers):
        '''Return the previous address from the address `ea` containing an instruction that uses `reg` or any one of the specified `regs`.'''
        return cls.prevreg(ea, utils.fconst(True), reg, *regs, **modifiers)
    @utils.multicase(ea=six.integer_types, predicate=builtins.callable, reg=(six.string_types, interface.register_t))
    @classmethod
    def prevreg(cls, ea, predicate, reg, *regs, **modifiers):
        '''Return the previous address from the address `ea` containing an instruction that uses `reg` or any one of the specified `regs` and satisfies the provided `predicate`.'''
        regs = (reg,) + regs
        count = modifiers.get('count', 1)
        args = u', '.join(["{:x}".format(ea)] + ["{!r}".format(predicate)] + ["\"{:s}\"".format(utils.string.escape(str(reg), '"')) for reg in regs])
        args = args + (u", {:s}".format(utils.string.kwargs(modifiers)) if modifiers else '')

        # generate each helper using the regmatch class
        iterops = interface.regmatch.modifier(**modifiers)
        uses_register = interface.regmatch.use(regs)

        # if within a function, then make sure we're within the chunk's bounds and we're a code type
        if function.within(ea):
            (start, _) = function.chunk(ea)
            fwithin = utils.fcompose(utils.fmap(functools.partial(operator.le, start), type.is_code), builtins.all)

        # otherwise ensure that we're not in the function and we're a code type.
        else:
            fwithin = utils.fcompose(utils.fmap(utils.fcompose(function.within, operator.not_), type.is_code), builtins.all)

            start = cls.__walk__(ea, cls.prev, fwithin)
            start = top() if start == idaapi.BADADDR else start

        # define a predicate for cls.walk to continue looping when true
        Freg = lambda ea: fwithin(ea) and not builtins.any(uses_register(ea, opnum) for opnum in iterops(ea))
        Fnot = utils.fcompose(predicate, operator.not_)
        F = utils.fcompose(utils.fmap(Freg, Fnot), builtins.any)

        ## skip the current address
        prevea = cls.prev(ea)
        if prevea is None:
            # FIXME: include registers in message
            logging.fatal(u"{:s}.prevreg({:s}) : Unable to start walking from the previous address of {:#x}.".format('.'.join([__name__, cls.__name__]), args, ea))
            return ea

        # now walk while none of our registers match
        res = cls.__walk__(prevea, cls.prev, F)
        if res in {None, idaapi.BADADDR} or (cls == address and res < start):
            # FIXME: include registers in message
            raise E.RegisterNotFoundError(u"{:s}.prevreg({:s}) : Unable to find register{:s} within the chunk {:#x}{:+#x}. Stopped at address {:#x}.".format('.'.join([__name__, cls.__name__]), args, '' if len(regs)==1 else 's', start, ea, res))

        # if the address is not a code type, then recurse so we can skip it.
        if not type.is_code(res):
            return cls.prevreg(res, predicate, *regs, **modifiers)

        # recurse if the user specified it
        modifiers['count'] = count - 1
        return cls.prevreg(res, predicate, *regs, **modifiers) if count > 1 else res

    @utils.multicase(reg=(six.string_types, interface.register_t))
    @classmethod
    def nextreg(cls, reg, *regs, **modifiers):
        '''Return the next address containing an instruction that uses `reg` or any one of the specified `regs`.'''
        return cls.nextreg(ui.current.address(), reg, *regs, **modifiers)
    @utils.multicase(predicate=builtins.callable, reg=(six.string_types, interface.register_t))
    @classmethod
    def nextreg(cls, predicate, reg, *regs, **modifiers):
        '''Return the next address containing an instruction uses `reg` or any one of the specified `regs` and satisfies the provided `predicate`.'''
        return cls.nextreg(ui.current.address(), predicate, reg, *regs, **modifiers)
    @utils.multicase(ea=six.integer_types, reg=(six.string_types, interface.register_t))
    @classmethod
    def nextreg(cls, ea, reg, *regs, **modifiers):
        '''Return the next address from the address `ea` containing an instruction that uses `reg` or any one of the specified `regs`.'''
        return cls.nextreg(ea, utils.fconst(True), reg, *regs, **modifiers)
    @utils.multicase(ea=six.integer_types, predicate=builtins.callable, reg=(six.string_types, interface.register_t))
    @classmethod
    def nextreg(cls, ea, predicate, reg, *regs, **modifiers):
        '''Return the next address from the address `ea` containing an instruction that uses `reg` or any one of the specified `regs` and satisfies the provided `predicate`.'''
        regs = (reg,) + regs
        count = modifiers.get('count', 1)
        args = u', '.join(["{:x}".format(ea)] + ["{!r}".format(predicate)] + ["\"{:s}\"".format(utils.string.escape(str(reg), '"')) for reg in regs])
        args = args + (u", {:s}".format(utils.string.kwargs(modifiers)) if modifiers else '')

        # generate each helper using the regmatch class
        iterops = interface.regmatch.modifier(**modifiers)
        uses_register = interface.regmatch.use(regs)

        # if within a function, then make sure we're within the chunk's bounds.
        if function.within(ea):
            (_, end) = function.chunk(ea)
            fwithin = utils.fcompose(utils.fmap(functools.partial(operator.gt, end), type.is_code), builtins.all)

        # otherwise ensure that we're not in a function and we're a code type.
        else:
            fwithin = utils.fcompose(utils.fmap(utils.fcompose(function.within, operator.not_), type.is_code), builtins.all)

            end = cls.__walk__(ea, cls.next, fwithin)
            end = bottom() if end == idaapi.BADADDR else end

        # define a predicate for cls.walk to continue looping when true
        Freg = lambda ea: fwithin(ea) and not builtins.any(uses_register(ea, opnum) for opnum in iterops(ea))
        Fnot = utils.fcompose(predicate, operator.not_)
        F = utils.fcompose(utils.fmap(Freg, Fnot), builtins.any)

        # skip the current address
        nextea = cls.next(ea)
        if nextea is None:
            # FIXME: include registers in message
            logging.fatal(u"{:s}.nextreg({:s}) : Unable to start walking from the next address of {:#x}.".format('.'.join([__name__, cls.__name__]), args, ea))
            return ea

        # now walk while none of our registers match
        res = cls.__walk__(nextea, cls.next, F)
        if res in {None, idaapi.BADADDR} or (cls == address and res >= end):
            # FIXME: include registers in message
            raise E.RegisterNotFoundError(u"{:s}.nextreg({:s}) : Unable to find register{:s} within chunk {:#x}{:+#x}. Stopped at address {:#x}.".format('.'.join([__name__, cls.__name__]), args, '' if len(regs)==1 else 's', ea, end, res))

        # if the address is not a code type, then recurse so we can skip it.
        if not type.is_code(res):
            return cls.nextreg(res, predicate, *regs, **modifiers)

        # recurse if the user specified it
        modifiers['count'] = count - 1
        return cls.nextreg(res, predicate, *regs, **modifiers) if count > 1 else res

    @utils.multicase(delta=six.integer_types)
    @classmethod
    def prevstack(cls, delta):
        '''Return the previous instruction from the current one that is past the specified sp `delta`.'''
        return cls.prevstack(ui.current.address(), delta)
    @utils.multicase(ea=six.integer_types, delta=six.integer_types)
    @classmethod
    def prevstack(cls, ea, delta):
        '''Return the previous instruction from the address `ea` that is past the specified sp `delta`.'''

        # FIXME: it'd be much better to keep track of this with a global class that wraps the logger
        if getattr(cls, '__prevstack_warning_count__', 0) == 0:
            logging.warning(u"{:s}.prevstack({:#x}, {:#x}) : This function's semantics are subject to change and may be deprecated in the future..".format('.'.join([__name__, cls.__name__]), ea, delta))
            cls.__prevstack_warning_count__ = getattr(cls, '__prevstack_warning_count__', 0) + 1

        # Get all the stack changes within the current function chunk, and the
        # current sp. This way we can bisect to found our starting point and
        # traverse backwards from there.
        points = [(item, sp) for item, sp in function.chunk.points(ea)]
        addresses = [item for item, _ in points]

        # Now we'll bisect our list of items in order to slice the points that
        # out that are completely irrelevant, and reverse the list so that
        # we can just walk it until we find the address that matches our argument.
        index = bisect.bisect_left(addresses, ea)
        filtered = points[:index][::-1]

        # Return the first entry in the list that has a delta (difference
        # between its sp and the starting address) that's larger than what
        # was requested by the user.
        start, position = function.get_spdelta(ea), cls.prev(ea)
        for address, sp in filtered:
            if delta <= abs(start - sp):
                return cls.next(position) if delta < abs(start - sp) else position
            position = cls.prev(address)

        # If we ran out of entries in the list, then save the last address
        # so that we can raise an exception to the user.
        else:
            fn, end = function.address(ea), address
        raise E.AddressOutOfBoundsError(u"{:s}.prevstack({:#x}, {:+#x}) : Unable to locate instruction matching contraints due to encountering the top ({:#x}) of the function {:#x}.".format('.'.join([__name__, cls.__name__]), ea, delta, end, fn))

    # FIXME: modify this to just locate _any_ amount of change in the sp delta by default
    @utils.multicase(delta=six.integer_types)
    @classmethod
    def nextstack(cls, delta):
        '''Return the next instruction from the current one that is past the sp `delta`.'''
        return cls.nextstack(ui.current.address(), delta)
    @utils.multicase(ea=six.integer_types, delta=six.integer_types)
    @classmethod
    def nextstack(cls, ea, delta):
        '''Return the next instruction from the address `ea` that is past the sp `delta`.'''

        # FIXME: it'd be much better to keep track of this with a global class that wraps the logger
        if getattr(cls, '__nextstack_warning_count__', 0) == 0:
            logging.warning(u"{:s}.nextstack({:#x}, {:#x}) : This function's semantics are subject to change and may be deprecatd in the future.".format('.'.join([__name__, cls.__name__]), ea, delta))
            cls.__nextstack_warning_count__ = getattr(cls, '__nextstack_warning_count__', 0) + 1

        # Get all the stack changes within the current function chunk, and the
        # current sp. This way we can bisect to find out where to start from
        # continue to walk forwards from there looking for our match.
        points = [(item, sp) for item, sp in function.chunk.points(ea)]
        addresses = [item for item, _ in points]

        # Now we'll bisect our list of items in order to select only the
        # point thats are relevant. This way we can just walk the list
        # until we find the address with the matching delta.
        index = bisect.bisect_right(addresses, ea)
        filtered = points[index:]

        # Traverse our filtered list until we find the first entry that
        # has the delta from the starting address that is larger than the
        # size that was requested by the user.
        start = function.get_spdelta(ea)
        for address, sp in filtered:
            if delta <= abs(start - sp):
                return cls.prev(address) if delta < abs(start - sp) else address
            continue

        # If we completed processing our filtered list, then we ran out
        # of addresses and need to save the address to raise an exception.
        else:
            fn, end = function.address(ea), address
        raise E.AddressOutOfBoundsError(u"{:s}.nextstack({:#x}, {:+#x}) : Unable to locate instruction matching contraints due to encountering the bottom ({:#x}) of the function {:#x}.".format('.'.join([__name__, cls.__name__]), ea, delta, end, fn))

    # FIXME: we should add aliases for a stack point as per the terminology that's used
    #        by IDA in its ``idaapi.func_t`` when getting points for a function or a chunk.
    prevdelta, nextdelta = utils.alias(prevstack, 'address'), utils.alias(nextstack, 'address')

    @utils.multicase()
    @classmethod
    def prevcall(cls, **count):
        '''Return the previous call instruction from the current address.'''
        return cls.prevcall(ui.current.address(), count.pop('count', 1))
    @utils.multicase(predicate=builtins.callable)
    @classmethod
    def prevcall(cls, predicate, **count):
        '''Return the previous call instruction from the current address that satisfies the provided `predicate`.'''
        return cls.prevcall(ui.current.address(), predicate, **count)
    @utils.multicase(ea=six.integer_types)
    @classmethod
    def prevcall(cls, ea):
        '''Return the previous call instruction from the address `ea`.'''
        return cls.prevcall(ea, 1)
    @utils.multicase(ea=six.integer_types, predicate=builtins.callable)
    @classmethod
    def prevcall(cls, ea, predicate, **count):
        '''Return the previous call instruction from the address `ea` that satisfies the provided `predicate`.'''
        F = utils.fcompose(utils.fmap(_instruction.type.is_call, predicate), builtins.all)
        return cls.prevF(ea, F, count.pop('count', 1))
    @utils.multicase(ea=six.integer_types, count=six.integer_types)
    @classmethod
    def prevcall(cls, ea, count):
        '''Return the previous `count` call instructions from the address `ea`.'''
        return cls.prevF(ea, _instruction.type.is_call, count)

    @utils.multicase()
    @classmethod
    def nextcall(cls, **count):
        '''Return the next call instruction from the current address.'''
        return cls.nextcall(ui.current.address(), count.pop('count', 1))
    @utils.multicase(predicate=builtins.callable)
    @classmethod
    def nextcall(cls, predicate, **count):
        '''Return the next call instruction from the current address that satisfies the provided `predicate`.'''
        return cls.nextcall(ui.current.address(), predicate, **count)
    @utils.multicase(ea=six.integer_types)
    @classmethod
    def nextcall(cls, ea):
        '''Return the next call instruction from the address `ea`.'''
        return cls.nextcall(ea, 1)
    @utils.multicase(ea=six.integer_types, predicate=builtins.callable)
    @classmethod
    def nextcall(cls, ea, predicate, **count):
        '''Return the next call instruction from the address `ea` that satisfies the provided `predicate`.'''
        F = utils.fcompose(utils.fmap(_instruction.type.is_call, predicate), builtins.all)
        return cls.nextF(ea, F, count.pop('count', 1))
    @utils.multicase(ea=six.integer_types, count=six.integer_types)
    @classmethod
    def nextcall(cls, ea, count):
        '''Return the next `count` call instructions from the address `ea`.'''
        return cls.nextF(ea, _instruction.type.is_call, count)

    @utils.multicase()
    @classmethod
    def prevbranch(cls, **count):
        '''Return the previous branch instruction from the current one.'''
        return cls.prevbranch(ui.current.address(), count.pop('count', 1))
    @utils.multicase(predicate=builtins.callable)
    @classmethod
    def prevbranch(cls, predicate, **count):
        '''Return the previous branch instruction from the current one that satisfies the provided `predicate`.'''
        return cls.prevbranch(ui.current.address(), predicate, **count)
    @utils.multicase(ea=six.integer_types)
    @classmethod
    def prevbranch(cls, ea):
        '''Return the previous branch instruction from the address `ea`.'''
        return cls.prevbranch(ea, 1)
    @utils.multicase(ea=six.integer_types, predicate=builtins.callable)
    @classmethod
    def prevbranch(cls, ea, predicate, **count):
        '''Return the previous branch instruction from the address `ea` that satisfies the provided `predicate`.'''
        Fnocall = utils.fcompose(_instruction.type.is_call, operator.not_)
        Fbranch = _instruction.type.is_branch
        Fx = utils.fcompose(utils.fmap(Fnocall, Fbranch), builtins.all)
        F = utils.fcompose(utils.fmap(Fx, predicate), builtins.all)
        return cls.prevF(ea, F, count.pop('count', 1))
    @utils.multicase(ea=six.integer_types, count=six.integer_types)
    @classmethod
    def prevbranch(cls, ea, count):
        '''Return the previous `count` branch instructions from the address `ea`.'''
        Fnocall = utils.fcompose(_instruction.type.is_call, operator.not_)
        Fbranch = _instruction.type.is_branch
        F = utils.fcompose(utils.fmap(Fnocall, Fbranch), builtins.all)
        return cls.prevF(ea, F, count)

    @utils.multicase()
    @classmethod
    def nextbranch(cls, **count):
        '''Return the next branch instruction from the current one.'''
        return cls.nextbranch(ui.current.address(), count.pop('count', 1))
    @utils.multicase(predicate=builtins.callable)
    @classmethod
    def nextbranch(cls, predicate, **count):
        '''Return the next branch instruction that satisfies the provided `predicate`.'''
        return cls.nextbranch(ui.current.address(), predicate, **count)
    @utils.multicase(ea=six.integer_types)
    @classmethod
    def nextbranch(cls, ea):
        '''Return the next branch instruction from the address `ea`.'''
        return cls.nextbranch(ea, 1)
    @utils.multicase(ea=six.integer_types, predicate=builtins.callable)
    @classmethod
    def nextbranch(cls, ea, predicate, **count):
        '''Return the next branch instruction from the address `ea` that satisfies the provided `predicate`.'''
        Fnocall = utils.fcompose(_instruction.type.is_call, operator.not_)
        Fbranch = _instruction.type.is_branch
        Fx = utils.fcompose(utils.fmap(Fnocall, Fbranch), builtins.all)
        F = utils.fcompose(utils.fmap(Fx, predicate), builtins.all)
        return cls.nextF(ea, F, count.pop('count', 1))
    @utils.multicase(ea=six.integer_types, count=six.integer_types)
    @classmethod
    def nextbranch(cls, ea, count):
        '''Return the next `count` branch instructions from the address `ea`.'''
        Fnocall = utils.fcompose(_instruction.type.is_call, operator.not_)
        Fbranch = _instruction.type.is_branch
        F = utils.fcompose(utils.fmap(Fnocall, Fbranch), builtins.all)
        return cls.nextF(ea, F, count)

    @utils.multicase(mnemonics=(six.string_types, builtins.list, builtins.set, builtins.tuple))
    @classmethod
    def prevmnemonic(cls, mnemonics):
        '''Return the address of the previous instruction from the current address that uses any of the specified `mnemonics`.'''
        return cls.prevmnemonic(ui.current.address(), mnemonics, 1)
    @utils.multicase(mnemonics=(six.string_types, builtins.list, builtins.set, builtins.tuple), predicate=builtins.callable)
    @classmethod
    def prevmnemonic(cls, mnemonics, predicate, **count):
        '''Return the address of the previous instruction from the current address that uses any of the specified `mnemonics` and satisfies the provided `predicate`.'''
        return cls.prevmnemonic(ui.current.address(), mnemonics, predicate, **count)
    @utils.multicase(mnemonics=(six.string_types, builtins.list, builtins.set, builtins.tuple), count=six.integer_types)
    @classmethod
    def prevmnemonic(cls, mnemonics, count):
        '''Return the address of the previous `count` instructions from the current address that uses any of the specified `mnemonics`.'''
        return cls.prevmnemonic(ui.current.address(), mnemonics, count)
    @utils.multicase(ea=six.integer_types, mnemonics=(six.string_types, builtins.list, builtins.set, builtins.tuple))
    @classmethod
    def prevmnemonic(cls, ea, mnemonics):
        '''Return the address of the previous instruction from the address `ea` that uses any of the specified `mnemonics`.'''
        return cls.prevmnemonic(ea, mnemonics, 1)
    @utils.multicase(ea=six.integer_types, mnemonics=(six.string_types, builtins.list, builtins.set, builtins.tuple), predicate=builtins.callable)
    @classmethod
    def prevmnemonic(cls, ea, mnemonics, predicate, **count):
        '''Return the address of the previous instruction from the address `ea` that uses any of the specified `mnemonics` and satisfies the provided `predicate`.'''
        items = {mnemonics} if isinstance(mnemonics, six.string_types) else {item for item in mnemonics}
        Fuses_mnemonics = utils.fcompose(_instruction.mnemonic, utils.fpartial(operator.contains, items))
        F = utils.fcompose(utils.fmap(Fuses_mnemonics, predicate), builtins.all)
        return cls.prevF(ea, F, count.pop('count', 1))
    @utils.multicase(ea=six.integer_types, mnemonics=(six.string_types, builtins.list, builtins.set, builtins.tuple), count=six.integer_types)
    @classmethod
    def prevmnemonic(cls, ea, mnemonics, count):
        '''Return the address of the previous `count` instructions from the address `ea` that uses any of the specified `mnemonics`.'''
        items = {mnemonics} if isinstance(mnemonics, six.string_types) else {item for item in mnemonics}
        Fuses_mnemonics = utils.fcompose(_instruction.mnemonic, utils.fpartial(operator.contains, items))
        return cls.prevF(ea, Fuses_mnemonics, count)

    @utils.multicase(mnemonics=(six.string_types, builtins.list, builtins.set, builtins.tuple))
    @classmethod
    def nextmnemonic(cls, mnemonics):
        '''Return the address of the next instruction from the current address that uses any of the specified `mnemonics`.'''
        return cls.nextmnemonic(ui.current.address(), mnemonics, 1)
    @utils.multicase(mnemonics=(six.string_types, builtins.list, builtins.set, builtins.tuple), predicate=builtins.callable)
    @classmethod
    def nextmnemonic(cls, mnemonics, predicate, **count):
        '''Return the address of the next instruction from the current address that uses any of the specified `mnemonics` and satisfies the provided `predicate`.'''
        return cls.nextmnemonic(ui.current.address(), mnemonics, predicate, **count)
    @utils.multicase(mnemonics=(six.string_types, builtins.list, builtins.set, builtins.tuple), count=six.integer_types)
    @classmethod
    def nextmnemonic(cls, mnemonics, count):
        '''Return the address of the next `count` instructions from the current address that uses any of the specified `mnemonics`.'''
        return cls.nextmnemonic(ui.current.address(), mnemonics, count)
    @utils.multicase(ea=six.integer_types, mnemonics=(six.string_types, builtins.list, builtins.set, builtins.tuple))
    @classmethod
    def nextmnemonic(cls, ea, mnemonics):
        '''Return the address of the next instruction from the address `ea` that uses any of the specified `mnemonics`.'''
        return cls.nextmnemonic(ea, mnemonics, 1)
    @utils.multicase(ea=six.integer_types, mnemonics=(six.string_types, builtins.list, builtins.set, builtins.tuple), predicate=builtins.callable)
    @classmethod
    def nextmnemonic(cls, ea, mnemonics, predicate, **count):
        '''Return the address of the next instruction from the address `ea` that uses any of the specified `mnemonics` and satisfies the provided `predicate`.'''
        items = {mnemonics} if isinstance(mnemonics, six.string_types) else {item for item in mnemonics}
        Fuses_mnemonics = utils.fcompose(_instruction.mnemonic, utils.fpartial(operator.contains, items))
        F = utils.fcompose(utils.fmap(Fuses_mnemonics, predicate), builtins.all)
        return cls.nextF(ea, F, count.pop('count', 1))
    @utils.multicase(ea=six.integer_types, mnemonics=(six.string_types, builtins.list, builtins.set, builtins.tuple), count=six.integer_types)
    @classmethod
    def nextmnemonic(cls, ea, mnemonics, count):
        '''Return the address of the next `count` instructions from the address `ea` that uses any of the specified `mnemonics`.'''
        items = {mnemonics} if isinstance(mnemonics, six.string_types) else {item for item in mnemonics}
        Fuses_mnemonics = utils.fcompose(_instruction.mnemonic, utils.fpartial(operator.contains, items))
        return cls.nextF(ea, Fuses_mnemonics, count)

    @utils.multicase()
    @classmethod
    def prevlabel(cls, **count):
        '''Return the address of the previous label from the current address.'''
        return cls.prevlabel(ui.current.address(), count.pop('count', 1))
    @utils.multicase(predicate=builtins.callable)
    @classmethod
    def prevlabel(cls, predicate, **count):
        '''Return the address of the previous label from the current address that satisfies the provided `predicate`.'''
        return cls.prevlabel(ui.current.address(), predicate, **count)
    @utils.multicase(ea=six.integer_types)
    @classmethod
    def prevlabel(cls, ea):
        '''Return the address of the previous label from the address `ea`.'''
        return cls.prevlabel(ea, 1)
    @utils.multicase(ea=six.integer_types, predicate=builtins.callable)
    @classmethod
    def prevlabel(cls, ea, predicate, **count):
        '''Return the address of the previous label from the address `ea` that satisfies the provided `predicate`.'''
        Flabel = type.has_label
        F = utils.fcompose(utils.fmap(Flabel, predicate), builtins.all)
        return cls.prevF(ea, F, count.pop('count', 1))
    @utils.multicase(ea=six.integer_types, count=six.integer_types)
    @classmethod
    def prevlabel(cls, ea, count):
        '''Return the address of the previous `count` labels from the address `ea`.'''
        return cls.prevF(ea, type.has_label, count)

    @utils.multicase()
    @classmethod
    def nextlabel(cls, **count):
        '''Return the address of the next label from the current address.'''
        return cls.nextlabel(ui.current.address(), count.pop('count', 1))
    @utils.multicase(predicate=builtins.callable)
    @classmethod
    def nextlabel(cls, predicate, **count):
        '''Return the address of the next label from the current address that satisfies the provided `predicate`.'''
        return cls.nextlabel(ui.current.address(), predicate, **count)
    @utils.multicase(ea=six.integer_types)
    @classmethod
    def nextlabel(cls, ea):
        '''Return the address of the next label from the address `ea`.'''
        return cls.nextlabel(ea, 1)
    @utils.multicase(ea=six.integer_types, predicate=builtins.callable)
    @classmethod
    def nextlabel(cls, ea, predicate, **count):
        '''Return the address of the next label from the address `ea` that satisfies the provided `predicate`.'''
        Flabel = type.has_label
        F = utils.fcompose(utils.fmap(Flabel, predicate), builtins.all)
        return cls.nextF(ea, F, count.pop('count', 1))
    @utils.multicase(ea=six.integer_types, count=six.integer_types)
    @classmethod
    def nextlabel(cls, ea, count):
        '''Return the address of the next `count` labels from the address `ea`.'''
        return cls.nextF(ea, type.has_label, count)

    @utils.multicase()
    @classmethod
    def prevcomment(cls, **repeatable):
        '''Return the previous address from the current one that has any type of comment.'''
        return cls.prevcomment(ui.current.address(), repeatable.pop('count', 1), **repeatable)
    @utils.multicase(predicate=builtins.callable)
    @classmethod
    def prevcomment(cls, predicate, **repeatable):
        '''Return the previous address from the current one that has any type of comment and satisfies the provided `predicate`.'''
        return cls.prevcomment(ui.current.address(), predicate, **repeatable)
    @utils.multicase(ea=six.integer_types)
    @classmethod
    def prevcomment(cls, ea, **repeatable):
        '''Return the previous address from the address `ea` that has any type of comment.'''
        return cls.prevcomment(ea, repeatable.pop('count', 1), **repeatable)
    @utils.multicase(ea=six.integer_types, predicate=builtins.callable)
    @classmethod
    def prevcomment(cls, ea, predicate, **repeatable):
        """Return the previous address from the address `ea` that has any type of comment and satisfies the provided `predicate`.

        If the bool `repeatable` is defined, then use it to determine whether to only track repeatable or non-repeatable comments.
        """
        if 'repeatable' in repeatable:
            Fcheck_comment = utils.fcompose(utils.frpartial(idaapi.get_cmt, not repeatable['repeatable']), utils.fpartial(operator.is_, None))
            Fx = utils.fcompose(utils.fmap(type.has_comment, Fcheck_comment), builtins.all)
        else:
            Fx = type.has_comment
        F = utils.fcompose(utils.fmap(Fx, predicate), builtins.all)
        return cls.prevF(ea, F, repeatable.pop('count', 1))
    @utils.multicase(ea=six.integer_types, count=six.integer_types)
    @classmethod
    def prevcomment(cls, ea, count, **repeatable):
        """Return the previous `count` addresses from the address `ea` that has any type of comment.

        If the bool `repeatable` is defined, then use it to determine whether to only track repeatable or non-repeatable comments.
        """
        if 'repeatable' in repeatable:
            Fcheck_comment = utils.fcompose(utils.frpartial(idaapi.get_cmt, not repeatable['repeatable']), utils.fpartial(operator.is_, None))
            F = utils.fcompose(utils.fmap(type.has_comment, Fcheck_comment), builtins.all)
        else:
            F = type.has_comment
        return cls.prevF(ea, F, count)

    @utils.multicase()
    @classmethod
    def nextcomment(cls, **repeatable):
        '''Return the next address from the current one that has any type of comment.'''
        return cls.nextcomment(ui.current.address(), repeatable.pop('count', 1), **repeatable)
    @utils.multicase(predicate=builtins.callable)
    @classmethod
    def nextcomment(cls, predicate, **repeatable):
        '''Return the next address from the current one that has any type of comment and satisfies the provided `predicate`.'''
        return cls.nextcomment(ui.current.address(), predicate, **repeatable)
    @utils.multicase(ea=six.integer_types)
    @classmethod
    def nextcomment(cls, ea, **repeatable):
        '''Return the next address from the address `ea` that has any type of comment.'''
        return cls.nextcomment(ea, repeatable.pop('count', 1), **repeatable)
    @utils.multicase(ea=six.integer_types, predicate=builtins.callable)
    @classmethod
    def nextcomment(cls, ea, predicate, **repeatable):
        """Return the next address from the address `ea` that has any type of comment and satisfies the provided `predicate`.

        If the bool `repeatable` is defined, then use it to determine whether to only track repeatable or non-repeatable comments.
        """
        if 'repeatable' in repeatable:
            Fcheck_comment = utils.fcompose(utils.frpartial(idaapi.get_cmt, not repeatable['repeatable']), utils.fpartial(operator.is_, None))
            Fx = utils.fcompose(utils.fmap(type.has_comment, Fcheck_comment), builtins.all)
        else:
            Fx = type.has_comment
        F = utils.fcompose(utils.fmap(Fx, predicate), builtins.all)
        return cls.nextF(ea, F, repeatable.pop('count', 1))
    @utils.multicase(ea=six.integer_types, count=six.integer_types)
    @classmethod
    def nextcomment(cls, ea, count, **repeatable):
        """Return the next `count` addresses from the address `ea` that has any type of comment.

        If the bool `repeatable` is defined, then use it to determine whether to only track repeatable or non-repeatable comments.
        """
        if 'repeatable' in repeatable:
            Fcheck_comment = utils.fcompose(utils.frpartial(idaapi.get_cmt, not repeatable['repeatable']), utils.fpartial(operator.is_, None))
            F = utils.fcompose(utils.fmap(type.has_comment, Fcheck_comment), builtins.all)
        else:
            F = type.has_comment
        return cls.nextF(ea, F, count)

    # FIXME: We should add the Or= or And= tests to this or we should allow specifying a set of tags.
    @utils.multicase()
    @classmethod
    @utils.string.decorate_arguments('tagname', 'tag', 'name')
    def prevtag(cls, **tagname):
        '''Return the previous address that contains a tag using the specified `tagname`.'''
        return cls.prevtag(ui.current.address(), tagname.pop('count', 1), **tagname)
    @utils.multicase(predicate=builtins.callable)
    @classmethod
    @utils.string.decorate_arguments('tagname', 'tag', 'name')
    def prevtag(cls, predicate, **tagname):
        '''Return the previous address that contains a tag using the specified `tagname` and satisfies the provided `predicate`.'''
        return cls.prevtag(ui.current.address(), predicate, **tagname)
    @utils.multicase(ea=six.integer_types)
    @classmethod
    @utils.string.decorate_arguments('tagname', 'tag', 'name')
    def prevtag(cls, ea, **tagname):
        '''Return the previous address from `ea` that contains a tag using the specified `tagname`.'''
        return cls.prevtag(ea, tagname.pop('count', 1), **tagname)
    @utils.multicase(ea=six.integer_types, predicate=builtins.callable)
    @classmethod
    @utils.string.decorate_arguments('tagname', 'tag', 'name')
    def prevtag(cls, ea, predicate, **tagname):
        '''Return the previous address from `ea` that contains a tag using the specified `tagname` and satisfies the provided `predicate`.'''
        tagname = builtins.next((tagname[kwd] for kwd in ['tagname', 'tag', 'name'] if kwd in tagname), None)
        Ftag = type.has_comment if tagname is None else utils.fcompose(tag, utils.frpartial(operator.contains, tagname))
        F = utils.fcompose(utils.fmap(Ftag, predicate), builtins.all)
        return cls.prevF(ea, F, tagname.pop('count', 1))
    @utils.multicase(ea=six.integer_types, count=six.integer_types)
    @classmethod
    @utils.string.decorate_arguments('tagname', 'tag', 'name')
    def prevtag(cls, ea, count, **tagname):
        '''Return the previous `count` addresses from `ea` that contains a tag using the specified `tagname`.'''
        tagname = builtins.next((tagname[kwd] for kwd in ['tagname', 'tag', 'name'] if kwd in tagname), None)
        Ftag = type.has_comment if tagname is None else utils.fcompose(tag, utils.frpartial(operator.contains, tagname))
        return cls.prevF(ea, Ftag, count)

    # FIXME: We should add the Or= or And= tests to this or we should allow specifying a set of tags.
    @utils.multicase()
    @classmethod
    @utils.string.decorate_arguments('tagname', 'tag', 'name')
    def nexttag(cls, **tagname):
        '''Return the next address that contains a tag using the specified `tagname`.'''
        return cls.nexttag(ui.current.address(), tagname.pop('count', 1), **tagname)
    @utils.multicase(predicate=builtins.callable)
    @classmethod
    @utils.string.decorate_arguments('tagname', 'tag', 'name')
    def nexttag(cls, predicate, **tagname):
        '''Return the next address that contains a tag using the specified `tagname` and satisfies the provided `predicate`.'''
        return cls.nexttag(ui.current.address(), predicate, **tagname)
    @utils.multicase(ea=six.integer_types)
    @classmethod
    @utils.string.decorate_arguments('tagname', 'tag', 'name')
    def nexttag(cls, ea, **tagname):
        '''Return the next address from `ea` that contains a tag using the specified `tagname`.'''
        return cls.nexttag(ea, tagname.pop('count', 1), **tagname)
    @utils.multicase(ea=six.integer_types, predicate=builtins.callable)
    @classmethod
    @utils.string.decorate_arguments('tagname', 'tag', 'name')
    def nexttag(cls, ea, predicate, **tagname):
        '''Return the next address from `ea` that contains a tag using the specified `tagname` and satisfies the provided `predicate`.'''
        tagname = builtins.next((tagname[kwd] for kwd in ['tagname', 'tag', 'name'] if kwd in tagname), None)
        Ftag = type.has_comment if tagname is None else utils.fcompose(tag, utils.frpartial(operator.contains, tagname))
        F = utils.fcompose(utils.fmap(Ftag, predicate), builtins.all)
        return cls.nextF(ea, F, tagname.pop('count', 1))
    @utils.multicase(ea=six.integer_types, count=six.integer_types)
    @classmethod
    @utils.string.decorate_arguments('tagname', 'tag', 'name')
    def nexttag(cls, ea, count, **tagname):
        '''Return the next `count` addresses from `ea` that contains a tag using the specified `tagname`.'''
        tagname = builtins.next((tagname[kwd] for kwd in ['tagname', 'tag', 'name'] if kwd in tagname), None)
        Ftag = type.has_comment if tagname is None else utils.fcompose(tag, utils.frpartial(operator.contains, tagname))
        return cls.nextF(ea, Ftag, count)

    @utils.multicase()
    @classmethod
    def prevunknown(cls, **count):
        '''Return the previous address from the current one that is undefined.'''
        return cls.prevunknown(ui.current.address(), count.pop('count', 1))
    @utils.multicase(predicate=builtins.callable)
    @classmethod
    def prevunknown(cls, predicate, **count):
        '''Return the previous address from the current one that is undefined and satisfies the provided `predicate`.'''
        return cls.prevunknown(ui.current.address(), predicate, **count)
    @utils.multicase(ea=six.integer_types)
    @classmethod
    def prevunknown(cls, ea):
        '''Return the previous address from the address `ea` that is undefined.'''
        return cls.prevunknown(ea, 1)
    @utils.multicase(ea=six.integer_types, predicate=builtins.callable)
    @classmethod
    def prevunknown(cls, ea, predicate, **count):
        '''Return the previous address from the address `ea` that is undefined and satisfies the provided `predicate`.'''
        F = utils.fcompose(utils.fmap(type.is_unknown, predicate), builtins.all)
        return cls.prevF(ea, F, count.pop('count', 1))
    @utils.multicase(ea=six.integer_types, count=six.integer_types)
    @classmethod
    def prevunknown(cls, ea, count):
        '''Return the previous `count` addresses from the address `ea` that is undefined.'''
        return cls.prevF(ea, type.is_unknown, count)

    @utils.multicase()
    @classmethod
    def nextunknown(cls, **count):
        '''Return the next address from the current one that is undefined.'''
        return cls.nextunknown(ui.current.address(), count.pop('count', 1))
    @utils.multicase(predicate=builtins.callable)
    @classmethod
    def nextunknown(cls, predicate, **count):
        '''Return the next address from the current one that is undefined and satisfies the provided `predicate`.'''
        return cls.nextunknown(ui.current.address(), predicate, **count)
    @utils.multicase(ea=six.integer_types)
    @classmethod
    def nextunknown(cls, ea):
        '''Return the next address from the address `ea` that is undefined.'''
        return cls.nextunknown(ea, 1)
    @utils.multicase(ea=six.integer_types, predicate=builtins.callable)
    @classmethod
    def nextunknown(cls, ea, predicate, **count):
        '''Return the next address from the address `ea` that is undefined and satisfies the provided `predicate`.'''
        F = utils.fcompose(utils.fmap(type.is_unknown, predicate), builtins.all)
        return cls.nextF(ea, F, count.pop('count', 1))
    @utils.multicase(ea=six.integer_types, count=six.integer_types)
    @classmethod
    def nextunknown(cls, ea, count):
        '''Return the next `count` addresses from the address `ea` that is undefined.'''
        return cls.nextF(ea, type.is_unknown, count)

    @utils.multicase()
    @classmethod
    def prevfunction(cls, **count):
        '''Return the previous address from the current address that is within a function.'''
        return cls.prevfunction(ui.current.address(), count.pop('count', 1))
    @utils.multicase(ea=six.integer_types)
    @classmethod
    def prevfunction(cls, ea):
        '''Return the previous address from the address `ea` that is within a function.'''
        return cls.prevfunction(ea, 1)
    @utils.multicase(ea=six.integer_types, predicate=builtins.callable)
    @classmethod
    def prevfunction(cls, ea, predicate, **count):
        '''Return the previous address from the address `ea` that is within a function and satisfies the provided `predicate`.'''
        F = utils.fcompose(utils.fmap(function.within, predicate), builtins.all)
        return cls.prevF(ea, F, count.pop('count', 1))
    @utils.multicase(ea=six.integer_types, count=six.integer_types)
    @classmethod
    def prevfunction(cls, ea, count):
        '''Return the previous `count` addresses from the address `ea` that is within a function.'''
        return cls.prevF(ea, function.within, count)

    @utils.multicase()
    @classmethod
    def nextfunction(cls, **count):
        '''Return the next address from the current address that is within a function.'''
        return cls.nextfunction(ui.current.address(), count.pop('count', 1))
    @utils.multicase(ea=six.integer_types)
    @classmethod
    def nextfunction(cls, ea):
        '''Return the next address from the address `ea` that is within a function.'''
        return cls.nextfunction(ea, 1)
    @utils.multicase(ea=six.integer_types, predicate=builtins.callable)
    @classmethod
    def nextfunction(cls, ea, predicate, **count):
        '''Return the next address from the address `ea` that is within a function and satisfies the provided `predicate`.'''
        F = utils.fcompose(utils.fmap(function.within, predicate), builtins.all)
        return cls.nextF(ea, F, count.pop('count', 1))
    @utils.multicase(ea=six.integer_types, count=six.integer_types)
    @classmethod
    def nextfunction(cls, ea, count):
        '''Return the next `count` addresses from the address `ea` that is within a function.'''
        return cls.nextF(ea, function.within, count)

    prevfunc, nextfunc = utils.alias(prevfunction, 'address'), utils.alias(nextfunction, 'address')

    # address translations
    @classmethod
    def by_offset(cls, offset):
        '''Return the specified `offset` translated to an address in the database.'''
        return config.baseaddress() + offset
    byoffset = utils.alias(by_offset, 'address')

    @utils.multicase()
    @classmethod
    def offset(cls):
        '''Return the current address translated to an offset relative to the base address of the database.'''
        return cls.offset(ui.current.address())
    @utils.multicase(ea=six.integer_types)
    @classmethod
    def offset(cls, ea):
        '''Return the address `ea` translated to an offset relative to the base address of the database.'''
        return interface.address.inside(ea) - config.baseaddress()
    getoffset = utils.alias(offset, 'address')

    @utils.multicase()
    @classmethod
    def fileoffset(cls):
        '''Return the file offset in the input file for the current address.'''
        return cls.fileoffset(ui.current.address())
    @utils.multicase(ea=six.integer_types)
    @classmethod
    def fileoffset(cls, ea):
        '''Return the file offset in the input file for the address `ea`.'''
        return idaapi.get_fileregion_offset(ea)

    @utils.multicase(offset=six.integer_types)
    @classmethod
    def by_fileoffset(cls, offset):
        '''Return the address in the database for the specified file `offset` of the input file.'''
        return idaapi.get_fileregion_ea(offset)
    byfileoffset = utils.alias(by_fileoffset, 'address')

a = addr = address  # XXX: ns alias

# address translations
offset = getoffset = get_offset = getOffset = utils.alias(address.offset, 'address')
byoffset = by_offset = byOffset = utils.alias(address.by_offset, 'address')

# datapoint navigation
prev, next = utils.alias(address.prev, 'address'), utils.alias(address.next, 'address')
prevref, nextref = utils.alias(address.prevref, 'address'), utils.alias(address.nextref, 'address')
prevreg, nextreg = utils.alias(address.prevreg, 'address'), utils.alias(address.nextreg, 'address')

class type(object):
    """
    This namespace is for fetching type information from the different
    addresses defined within the database. The functions within this
    namespace allow one to extract various type information from the
    different locations within the database.

    This namespace is also aliased as ``database.t``.

    By default, this namespace will return the ``idaapi.DT_TYPE`` of the
    specified address.

    Some examples of using this namespace can be::

        > print( database.type.size(ea) )
        > print( database.type.is_initialized(ea) )
        > print( database.type.is_data(ea) )
        > length = database.t.array.length(ea)
        > st = database.t.structure(ea)

    """

    @utils.multicase()
    def __new__(cls):
        '''Return the type information for the current address as an ``idaapi.tinfo_t``.'''
        return cls(ui.current.address())
    @utils.multicase(ea=six.integer_types)
    def __new__(cls, ea):
        '''Return the type information for the address `ea` as an ``idaapi.tinfo_t``.'''
        get_tinfo = (lambda ti, ea: idaapi.get_tinfo2(ea, ti)) if idaapi.__version__ < 7.0 else idaapi.get_tinfo

        # First try and get the actual typeinfo for the given address. If it
        # actually worked, then we can just return it as-is.
        ti = idaapi.tinfo_t()
        if get_tinfo(ti, ea):
            return ti

        # Otherwise we'll go ahead and guess the typeinfo for the same address.
        res = idaapi.guess_tinfo2(ea, ti) if idaapi.__version__ < 7.0 else idaapi.guess_tinfo(ti, ea)

        # If we failed, then we'll try and hack around it using idaapi.print_type.
        if res != idaapi.GUESS_FUNC_OK:
            fl = idaapi.PRTYPE_1LINE
            info_s = idaapi.print_type(ea, fl)

            # If we still couldn't get the typeinfo, then return None because
            # there isn't any typeinfo associated with the specified address.
            if info_s is None:
                return None

            # Parse the type information string that IDA gave us and return it.
            ti = internal.declaration.parse(info_s)
            if ti is None:
                raise E.InvalidTypeOrValueError(u"{:s}.info({:#x}) : Unable to parse the returned type declaration ({!s}).".format('.'.join([__name__, cls.__name__]), ea, utils.string.repr(info_s)))
            return ti
        return ti
    @utils.multicase(none=None.__class__)
    def __new__(cls, none):
        '''Remove the type information from the current address.'''
        return cls(ui.current.address(), None)
    @utils.multicase(info=(six.string_types, idaapi.tinfo_t))
    def __new__(cls, info, **guessed):
        '''Apply the type information in `info` to the current address.'''
        return cls(ui.current.address(), info, **guessed)
    @utils.multicase(ea=six.integer_types, info=idaapi.tinfo_t)
    def __new__(cls, ea, info, **guessed):
        """Apply the ``idaapi.tinfo_t`` in `info` to the address `ea`.

        If `guess` is true, then apply the type information as a guess.
        If `force` is true, then apply the type as-is regardless of its location.
        """
        TINFO_GUESSED, TINFO_DEFINITE = getattr(idaapi, 'TINFO_GUESSED', 0), getattr(idaapi, 'TINFO_DEFINITE', 1)
        info_s = "{!s}".format(info)

        # Check if we're pointing directly at a function, because if we are,
        # then we need to use function.type instead.
        try:
            rt, ea = interface.addressOfRuntimeOrStatic(ea)
            if not rt:
                return function.type(ea, info)

        except E.FunctionNotFoundError:
            pass

        # If we didn't exception, then that means we're pointing at a runtime
        # address. If we are then we need to ensure that our type is a pointer.
        else:
            ti = idaapi.tinfo_t()
            if any([info.is_ptr(), info.is_func()]) or builtins.next((guessed[kwd] for kwd in ['force', 'forced'] if kwd in guessed), False):
                ti, ok = info, True

            # If it's not a pointer then we need to promote it.
            else:
                logging.warning(u"{:s}.info({:#x}, {!s}) : Promoting the given type ({!s}) to a pointer before applying it to the runtime-linked address ({:#x}).".format('.'.join([__name__, cls.__name__]), ea, utils.string.repr(info_s), utils.string.repr(info_s), ea))
                pi = idaapi.ptr_type_data_t()
                pi.obj_type = info
                ok = ti.create_ptr(pi)

            # If we couldn't promote it to a pointer, then we need to bail so we
            # don't damage anything that the user might not have intended to do.
            if not ok:
                raise E.DisassemblerError(u"{:s}.info({:#x}, {!s}) : Unable to promote type ({!s}) to a pointer for the runtime-linked address ({:#x}).".format('.'.join([__name__, cls.__name__]), ea, utils.string.repr(info_s), utils.string.repr(info_s), ea))
            info = ti

        # All we need to do is to use idaapi to apply our tinfo_t to the address.
        result, ok = cls(ea), idaapi.apply_tinfo(ea, info, TINFO_DEFINITE)
        if not ok:
            raise E.DisassemblerError(u"{:s}.info({:#x}, {!s}) : Unable to apply typeinfo ({!s}) to the address ({:#x}).".format('.'.join([__name__, cls.__name__]), ea, utils.string.repr(info_s), utils.string.repr(info_s), ea))

        # TINFO_GUESSED doesn't appear to work, so instead we'll force the option
        # here by clearing the aflag if the user wants to mark this as guessed.
        if builtins.next((guessed[kwd] for kwd in ['guess', 'guessed'] if kwd in guessed), False):
            interface.node.aflags(ea, idaapi.AFL_USERTI, 0)
        return result
    @utils.multicase(none=None.__class__)
    def __new__(cls, ea, none):
        '''Remove the type information from the address `ea`.'''
        del_tinfo = idaapi.del_tinfo2 if idaapi.__version__ < 7.0 else idaapi.del_tinfo

        # Grab the previous typeinfo if there was something there, and coerce
        # it to None if we got an error of some sort.
        try:
            ti = cls(ea)

        except E.DisassemblerError:
            ti = None

        result, _ = ti, del_tinfo(ea)
        return result
    @utils.multicase(ea=six.integer_types, string=six.string_types)
    @utils.string.decorate_arguments('string')
    def __new__(cls, ea, string, **guessed):
        '''Parse the type information in `string` into an ``idaapi.tinfo_t`` and apply it to the address `ea`.'''

        # Check if we're pointing directly at a function, because if we are,
        # then we need to use function.type instead.
        try:
            rt, ea = interface.addressOfRuntimeOrStatic(ea)
            if not rt:
                return function.type(ea, string)

        except E.FunctionNotFoundError:
            pass

        # Now we can just ask IDA to parse this into a tinfo_t for us and then recurse
        # into ourselves. If we received None, then that's pretty much a parsing error.
        ti = internal.declaration.parse(string)
        if ti is None:
            raise E.InvalidTypeOrValueError(u"{:s}.info({:#x}) : Unable to parse the specified type declaration ({!s}).".format('.'.join([__name__, cls.__name__]), ea, utils.string.repr(string)))
        return cls(ea, ti, **guessed)

    @utils.multicase()
    @classmethod
    def size(cls):
        '''Return the size of the item at the current address.'''
        return size(ui.current.address())
    @utils.multicase(ea=six.integer_types)
    @classmethod
    def size(cls, ea):
        '''Return the size of the item at the address `ea`.'''
        ea = interface.address.within(ea)
        return idaapi.get_item_size(ea)

    @utils.multicase()
    @classmethod
    def flags(cls):
        '''Return the flags of the item at the current address.'''
        return cls.flags(ui.current.address())
    @utils.multicase(ea=six.integer_types)
    @classmethod
    def flags(cls, ea):
        '''Return the flags of the item at the address `ea`.'''
        getflags = idaapi.getFlags if idaapi.__version__ < 7.0 else idaapi.get_full_flags
        return getflags(interface.address.within(ea))
    @utils.multicase(ea=six.integer_types, mask=six.integer_types)
    @classmethod
    def flags(cls, ea, mask):
        '''Return the flags at the address `ea` masked with `mask`.'''
        getflags = idaapi.getFlags if idaapi.__version__ < 7.0 else idaapi.get_full_flags
        return getflags(interface.address.within(ea)) & idaapi.as_uint32(mask)
    @utils.multicase(ea=six.integer_types, mask=six.integer_types, value=six.integer_types)
    @classmethod
    def flags(cls, ea, mask, value):
        '''Sets the flags at the address `ea` masked with `mask` set to `value`.'''
        if idaapi.__version__ < 7.0:
            ea = interface.address.within(ea)
            res = idaapi.getFlags(ea)
            idaapi.setFlags(ea, (res & ~mask) | value)
            return res & mask
        raise E.UnsupportedVersion(u"{:s}.flags({:#x}, {:#x}, {:d}) : IDA 7.0 has unfortunately deprecated `idaapi.setFlags(...)`.".format('.'.join([__name__, cls.__name__]), ea, mask, value))

    @utils.multicase()
    @staticmethod
    def is_initialized():
        '''Return if the current address is initialized.'''
        return type.is_initialized(ui.current.address())
    @utils.multicase(ea=six.integer_types)
    @staticmethod
    def is_initialized(ea):
        '''Return if the address specified by `ea` is initialized.'''
        return type.flags(interface.address.within(ea), idaapi.FF_IVL) == idaapi.FF_IVL
    @utils.multicase(ea=six.integer_types, size=six.integer_types)
    @staticmethod
    def is_initialized(ea, size):
        '''Return if the address specified by `ea` up to `size` bytes is initialized.'''
        ea = interface.address.within(ea)
        return all(type.flags(ea + offset, idaapi.FF_IVL) == idaapi.FF_IVL for offset in builtins.range(size))
    initializedQ = utils.alias(is_initialized, 'type')

    @utils.multicase()
    @staticmethod
    def is_code():
        '''Return if the current address is marked as code.'''
        return type.is_code(ui.current.address())
    @utils.multicase(ea=six.integer_types)
    @staticmethod
    def is_code(ea):
        '''Return if the address specified by `ea` is marked as code.'''
        return type.flags(interface.address.within(ea), idaapi.MS_CLS) == idaapi.FF_CODE
    @utils.multicase(ea=six.integer_types, size=six.integer_types)
    @staticmethod
    def is_code(ea, size):
        '''Return if the address specified by `ea` up to `size` bytes is marked as code.'''
        ea = interface.address.within(ea)
        return all(type.flags(ea + offset, idaapi.MS_CLS) == idaapi.FF_CODE for offset in builtins.range(size))
    codeQ = utils.alias(is_code, 'type')

    @utils.multicase()
    @staticmethod
    def is_data():
        '''Return if the current address is marked as data.'''
        return type.is_data(ui.current.address())
    @utils.multicase(ea=six.integer_types)
    @staticmethod
    def is_data(ea):
        '''Return if the address specified by `ea` is marked as data.'''
        return type.flags(interface.address.within(ea), idaapi.MS_CLS) == idaapi.FF_DATA
    @utils.multicase(ea=six.integer_types, size=six.integer_types)
    @staticmethod
    def is_data(ea, size):
        '''Return if the address specified by `ea` up to `size` bytes is marked as data.'''
        ea = interface.address.within(ea)
        return all(type.flags(ea + offset, idaapi.MS_CLS) == idaapi.FF_DATA for offset in builtins.range(size))
    dataQ = utils.alias(is_data, 'type')

    # True if ea marked unknown
    @utils.multicase()
    @staticmethod
    def is_unknown():
        '''Return if the current address is marked as unknown.'''
        return type.is_unknown(ui.current.address())
    @utils.multicase(ea=six.integer_types)
    @staticmethod
    def is_unknown(ea):
        '''Return if the address specified by `ea` is marked as unknown.'''
        return type.flags(interface.address.within(ea), idaapi.MS_CLS) == idaapi.FF_UNK
    @utils.multicase(ea=six.integer_types, size=six.integer_types)
    @staticmethod
    def is_unknown(ea, size):
        '''Return if the address specified by `ea` up to `size` bytes is marked as unknown.'''
        ea = interface.address.within(ea)
        return all(type.flags(ea + offset, idaapi.MS_CLS) == idaapi.FF_UNK for offset in builtins.range(size))
    unknownQ = is_undefined = undefinedQ = utils.alias(is_unknown, 'type')

    @utils.multicase()
    @staticmethod
    def is_head():
        '''Return if the current address is aligned to a definition in the database.'''
        return type.is_head(ui.current.address())
    @utils.multicase(ea=six.integer_types)
    @staticmethod
    def is_head(ea):
        '''Return if the address `ea` is aligned to a definition in the database.'''
        return type.flags(interface.address.within(ea), idaapi.FF_DATA) != 0
    headQ = utils.alias(is_head, 'type')

    @utils.multicase()
    @staticmethod
    def is_tail():
        '''Return if the current address is not aligned to a definition in the database.'''
        return type.is_tail(ui.current.address())
    @utils.multicase(ea=six.integer_types)
    @staticmethod
    def is_tail(ea):
        '''Return if the address `ea` is not aligned to a definition in the database.'''
        return type.flags(interface.address.within(ea), idaapi.MS_CLS) == idaapi.FF_TAIL
    tailQ = utils.alias(is_tail, 'type')

    @utils.multicase()
    @staticmethod
    def is_align():
        '''Return if the current address is defined as an alignment.'''
        return type.is_align(ui.current.address())
    @utils.multicase(ea=six.integer_types)
    @staticmethod
    def is_align(ea):
        '''Return if the address at `ea` is defined as an alignment.'''
        is_align = idaapi.isAlign if idaapi.__version__ < 7.0 else idaapi.is_align
        return is_align(type.flags(ea))
    alignQ = utils.alias(is_align, 'type')

    @utils.multicase()
    @staticmethod
    def has_comment():
        '''Return if the current address is commented.'''
        return type.has_comment(ui.current.address())
    @utils.multicase(ea=six.integer_types)
    @staticmethod
    def has_comment(ea):
        '''Return if the address at `ea` is commented.'''
        return type.flags(interface.address.within(ea), idaapi.FF_COMM) == idaapi.FF_COMM
    commentQ = utils.alias(has_comment, 'type')

    @utils.multicase()
    @staticmethod
    def has_reference():
        '''Return if the current address is referencing another address.'''
        return type.has_reference(ui.current.address())
    @utils.multicase(ea=six.integer_types)
    @staticmethod
    def has_reference(ea):
        '''Return if the address at `ea` is referencing another address.'''
        return type.flags(interface.address.within(ea), idaapi.FF_REF) == idaapi.FF_REF
    referenceQ = refQ = utils.alias(has_reference, 'type')

    @utils.multicase()
    @staticmethod
    def has_label():
        '''Return if the current address has a label.'''
        return type.has_label(ui.current.address())
    @utils.multicase(ea=six.integer_types)
    @staticmethod
    def has_label(ea):
        '''Return if the address at `ea` has a label.'''
        return idaapi.has_any_name(type.flags(ea)) or type.has_dummyname(ea) or type.has_customname(ea)
    labelQ = nameQ = has_name = utils.alias(has_label, 'type')

    @utils.multicase()
    @staticmethod
    def has_customname():
        '''Return if the current address has a custom name.'''
        return type.has_customname(ui.current.address())
    @utils.multicase(ea=six.integer_types)
    @staticmethod
    def has_customname(ea):
        '''Return if the address at `ea` has a custom name.'''
        return type.flags(interface.address.within(ea), idaapi.FF_NAME) == idaapi.FF_NAME
    customnameQ = utils.alias(has_customname, 'type')

    @utils.multicase()
    @staticmethod
    def has_dummyname():
        '''Return if the current address has a dummy name.'''
        return type.has_dummyname(ui.current.address())
    @utils.multicase(ea=six.integer_types)
    @staticmethod
    def has_dummyname(ea):
        '''Return if the address at `ea` has a dummy name.'''
        return type.flags(ea, idaapi.FF_LABL) == idaapi.FF_LABL
    dummynameQ = utils.alias(has_dummyname, 'type')

    @utils.multicase()
    @staticmethod
    def has_autoname():
        '''Return if the current address was automatically named.'''
        return type.has_autoname(ui.current.address())
    @utils.multicase(ea=six.integer_types)
    @staticmethod
    def has_autoname(ea):
        '''Return if the address `ea` was automatically named.'''
        return idaapi.has_auto_name(type.flags(ea))
    autonameQ = utils.alias(has_autoname, 'type')

    @utils.multicase()
    @staticmethod
    def has_publicname():
        '''Return if the current address has a public name.'''
        return type.has_publicname(ui.current.address())
    @utils.multicase(ea=six.integer_types)
    @staticmethod
    def has_publicname(ea):
        '''Return if the address at `ea` has a public name.'''
        return idaapi.is_public_name(interface.address.within(ea))
    publicnameQ = utils.alias(has_publicname, 'type')

    @utils.multicase()
    @staticmethod
    def has_weakname():
        '''Return if the current address has a name with a weak type.'''
        return type.has_weakname(ui.current.address())
    @utils.multicase(ea=six.integer_types)
    @staticmethod
    def has_weakname(ea):
        '''Return if the address at `ea` has a name with a weak type.'''
        return idaapi.is_weak_name(interface.address.within(ea))
    weaknameQ = utils.alias(has_weakname, 'type')

    @utils.multicase()
    @staticmethod
    def has_listedname():
        '''Return if the current address has a name that is listed.'''
        return type.has_listedname(ui.current.address())
    @utils.multicase(ea=six.integer_types)
    @staticmethod
    def has_listedname(ea):
        '''Return if the address at `ea` has a name that is listed.'''
        return idaapi.is_in_nlist(interface.address.within(ea))
    listednameQ = utils.alias(has_listedname, 'type')

    @utils.multicase()
    @staticmethod
    def has_typeinfo():
        '''Return if the current address has any type information associated with it.'''
        return type.has_typeinfo(ui.current.address())
    @utils.multicase(ea=six.integer_types)
    @staticmethod
    def has_typeinfo(ea):
        '''Return if the address at `ea` has any type information associated with it.'''
        try:
            ok = type(ea) is not None

        # If we got an exception raised, then we were unable to parse this type
        # properly. Prior to failing, check to see if the name is a mangled C++
        # symbol that contains type information.
        except E.InvalidTypeOrValueError as e:
            #logging.warning(u"{:s}.has_typeinfo({:#x}) : Unable to interpret the type information at address {:#x}.".format('.'.join([__name__, type.__name__]), ea, ea), exc_info=True)
            realname = name(ea)
            ok = internal.declaration.demangle(realname) != realname
        return ok
    typeinfoQ = infoQ = utils.alias(has_typeinfo, 'type')

    @utils.multicase()
    @staticmethod
    def is_string():
        '''Return if the current address is defined as a string.'''
        return type.is_string(ui.current.address())
    @utils.multicase(ea=six.integer_types)
    @staticmethod
    def is_string(ea):
        '''Return if the address at `ea` is defined as a string.'''
        FF_STRLIT = idaapi.FF_STRLIT if hasattr(idaapi, 'FF_STRLIT') else idaapi.FF_ASCI
        return type.flags(ea, idaapi.DT_TYPE) == FF_STRLIT
    stringQ = utils.alias(is_string, 'type')

    @utils.multicase()
    @staticmethod
    def is_structure():
        '''Return if the current address is defined as a structure.'''
        return type.is_structure(ui.current.address())
    @utils.multicase(ea=six.integer_types)
    @staticmethod
    def is_structure(ea):
        '''Return if the address at `ea` is defined as a structure.'''
        FF_STRUCT = idaapi.FF_STRUCT if hasattr(idaapi, 'FF_STRUCT') else idaapi.FF_STRU
        return type.flags(ea, idaapi.DT_TYPE) == FF_STRUCT
    structQ = structureQ = is_struc = is_struct = utils.alias(is_structure, 'type')

    @utils.multicase()
    @staticmethod
    def is_reference():
        '''Return if the data at the current address is referenced by another address.'''
        return type.is_reference(ui.current.address())
    @utils.multicase(ea=six.integer_types)
    @staticmethod
    def is_reference(ea):
        '''Return if the data at the address `ea` is referenced by another address.'''
        X, flags = idaapi.xrefblk_t(), idaapi.XREF_FAR | idaapi.XREF_DATA
        return X.first_to(ea, flags)
    is_ref = is_referenced = utils.alias(is_reference, 'type')

    class array(object):
        """
        This namespace is for returning type information about an array
        that is defined within the database. By default this namespace
        will return the array's element type and its number of elements
        as a list `[size, count]`.

        Some examples of using this namespace can be::

            > type, length = database.t.array()
            > print( database.t.array.size(ea) )
            > print( database.t.array.member(ea) )
            > print( database.t.array.element(ea) )
            > print( database.t.array.length(ea) )

        """
        @utils.multicase()
        def __new__(cls):
            '''Return the `[type, length]` of the array at the current address.'''
            address, selection = ui.current.address(), ui.current.selection()
            if operator.eq(*(internal.interface.address.head(ea, silent=True) for ea in selection)):
                return cls(address)
            return cls(selection)
        @utils.multicase(ea=six.integer_types)
        def __new__(cls, ea):
            '''Return the `[type, length]` of the array at the address specified by `ea`.'''
            return cls(ea, idaapi.get_item_size(ea))
        @utils.multicase(bounds=tuple)
        def __new__(cls, bounds):
            '''Return the `[type, length]` of the specified `bounds` as an array.'''
            left, right = ea, _ = sorted(bounds)
            return cls(ea, max(0, right - left))
        @utils.multicase(ea=six.integer_types)
        def __new__(cls, ea, size):
            '''Return the `[type, length]` of the address `ea` if it was an array using the specified `size` (in bytes).'''
            ea = interface.address.head(ea)
            F, ti, cb = type.flags(ea), idaapi.opinfo_t(), abs(size)

            # get the opinfo at the current address to verify if there's a structure or not
            ok = idaapi.get_opinfo(ea, 0, F, ti) if idaapi.__version__ < 7.0 else idaapi.get_opinfo(ti, ea, 0, F)
            tid = ti.tid if ok else idaapi.BADADDR

            # convert it to a pythonic type using the address we were given.
            res = interface.typemap.dissolve(F, tid, cb, offset=min(ea, ea + size))

            # if it's a list, then validate the result and return it
            if isinstance(res, list):
                element, length = res

                # if the address is a string type, then we need to know the prefix size
                # so that we can add it to our length to work around the difference
                # between how these sizes are calc'd in structs versus addresses.
                if isinstance(element, tuple) and len(element) == 3:
                    _, width, extra = element
                    return [element, length - extra // width]

                # simply return the element that we resolved.
                return [element, length]

            # this shouldn't ever happen, but if it does then it's a
            # single element array
            return [res, 1]

        @utils.multicase()
        @classmethod
        def member(cls):
            '''Return the type for the member of the array at the current address.'''
            return cls.member(ui.current.address())
        @utils.multicase(ea=six.integer_types)
        @classmethod
        def member(cls, ea):
            '''Return the type for the member of the array at the address specified by `ea`.'''
            res, _ = cls(ea)
            return res

        @utils.multicase()
        @classmethod
        def element(cls):
            '''Return the type information for the member of the array defined at the current address.'''
            return cls.element(ui.current.address())
        @utils.multicase(ea=six.integer_types)
        @classmethod
        def element(cls, ea):
            '''Return the type information for the member of the array defined at the address specified by `ea`.'''
            ti = type(ea)
            if ti is None:
                raise E.MissingTypeOrAttribute(u"{:s}.info({:#x}) : Unable to fetch any type information from the address at {:#x}.".format('.'.join([__name__, 'type', cls.__name__]), ea, ea))
            return ti.get_array_element() if ti.is_array() else ti
        info = typeinfo = utils.alias(element, 'type.array')

        @utils.multicase()
        @classmethod
        def size(cls):
            '''Return the size of a member in the array at the current address.'''
            return cls.size(ui.current.address())
        @utils.multicase(ea=six.integer_types)
        @classmethod
        def size(cls, ea):
            '''Return the size of a member in the array at the address specified by `ea`.'''
            ea, FF_STRUCT = interface.address.head(ea), idaapi.FF_STRUCT if hasattr(idaapi, 'FF_STRUCT') else idaapi.FF_STRU
            F, T = type.flags(ea), type.flags(ea, idaapi.DT_TYPE)
            return _structure.size(type.structure.id(ea)) if T == FF_STRUCT else idaapi.get_full_data_elsize(ea, F)

        @utils.multicase()
        @classmethod
        def length(cls):
            '''Return the number of members in the array at the current address.'''
            return cls.length(ui.current.address())
        @utils.multicase(ea=six.integer_types)
        @classmethod
        def length(cls, ea):
            '''Return the number of members in the array at the address specified by `ea`.'''
            ea = interface.address.head(ea)
            sz, ele = idaapi.get_item_size(ea), idaapi.get_full_data_elsize(ea, type.flags(ea))
            return sz // ele

    class structure(object):
        """
        This namespace for returning type information about a structure
        that is defined within the database. By default this namespace
        will return the ``structure_t`` at the given address.

        Some of the ways to use this namespace are::

            > st = database.t.struct()
            > print( database.t.struct.size() )
            > st = structure.by(database.t.id(ea))

        """
        @utils.multicase()
        def __new__(cls):
            '''Return the structure type at the current address.'''
            return cls(ui.current.address())
        @utils.multicase(ea=six.integer_types)
        def __new__(cls, ea):
            '''Return the structure type at address `ea`.'''
            ea = interface.address.head(ea)
            res = cls.id(ea)
            return _structure.by(res, offset=ea)

        @utils.multicase()
        @classmethod
        def id(cls):
            '''Return the identifier of the structure at the current address.'''
            return cls.id(ui.current.address())
        @utils.multicase(ea=six.integer_types)
        @classmethod
        def id(cls, ea):
            '''Return the identifier of the structure at address `ea`.'''
            ea, FF_STRUCT = interface.address.head(ea), idaapi.FF_STRUCT if hasattr(idaapi, 'FF_STRUCT') else idaapi.FF_STRU

            res = type.flags(ea, idaapi.DT_TYPE)
            if res != FF_STRUCT:
                raise E.MissingTypeOrAttribute(u"{:s}.id({:#x}) : The type at specified address is not an FF_STRUCT({:#x}) and is instead {:#x}.".format('.'.join([__name__, 'type', cls.__name__]), ea, FF_STRUCT, res))

            ti, F = idaapi.opinfo_t(), type.flags(ea)
            res = idaapi.get_opinfo(ea, 0, F, ti) if idaapi.__version__ < 7.0 else idaapi.get_opinfo(ti, ea, 0, F)
            if not res:
                raise E.DisassemblerError(u"{:s}.id({:#x}) : The call to `idaapi.get_opinfo()` failed at {:#x}.".format('.'.join([__name__, 'type', cls.__name__]), ea, ea))
            return ti.tid

        @utils.multicase()
        @classmethod
        def size(cls):
            '''Return the total size of the structure at the current address.'''
            return cls.size(ui.current.address())
        @utils.multicase(ea=six.integer_types)
        @classmethod
        def size(cls, ea):
            '''Return the total size of the structure at address `ea`.'''
            id = cls.id(ea)
            ptr = idaapi.get_struc(id)
            return idaapi.get_struc_size(ptr)
    struc = struct = structure  # ns alias

    @utils.multicase()
    @classmethod
    def switch(cls):
        '''Return the switch_t at the current address.'''
        return get.switch(ui.current.address())
    @utils.multicase(ea=six.integer_types)
    @classmethod
    def switch(cls, ea):
        '''Return the switch_t at the address `ea`.'''
        return get.switch(ea)

    @utils.multicase()
    @staticmethod
    def is_importref():
        '''Return true if the instruction at the current address references an import.'''
        return type.is_importref(ui.current.address())
    @utils.multicase(ea=six.integer_types)
    @staticmethod
    def is_importref(ea):
        '''Return true if the instruction at `ea` references an import.'''
        ea = interface.address.inside(ea)

        # FIXME: this doesn't seem like the right way to determine an instruction is reffing an import
        datarefs, coderefs = xref.data_down(ea), xref.code_down(ea)
        return len(datarefs) == len(coderefs) and len(coderefs) > 0
    isimportref = importrefQ = utils.alias(is_importref, 'type')

    @utils.multicase()
    @staticmethod
    def is_globalref():
        '''Return true if the instruction at the current address references a global.'''
        return is_globalref(ui.current.address())
    @utils.multicase(ea=six.integer_types)
    @staticmethod
    def is_globalref(ea):
        '''Return true if the instruction at `ea` references a global.'''
        ea = interface.address.inside(ea)

        # FIXME: this doesn't seem like the right way to determine this...
        datarefs, coderefs = xref.data_down(ea), xref.code_down(ea)
        return len(datarefs) > len(coderefs)
    isglobalref = globalrefQ = utils.alias(is_globalref, 'type')

    @utils.multicase()
    @classmethod
    def is_exception(cls, **flags):
        '''Return if the current address or selection is guarded by an exception or part of an exception handler.'''
        address, selection = ui.current.address(), ui.current.selection()
        if operator.eq(*(internal.interface.address.head(ea, silent=True) for ea in selection)):
            return cls.is_exception(address, **flags)
        return cls.is_exception(address, **flags)
    @utils.multicase(ea=(six.integer_types, builtins.tuple))
    @classmethod
    def is_exception(cls, ea, **flags):
        """Return if the address or boundaries in `ea` is guarded by an exception or part of an exception handler.

        If `seh` or `cpp` is specified, then include or exclude that exception type.
        If `guarded` or `try` is true, then return if the address is guarded by an exception.
        If `handler` or `catch` is true, then return if the address is part of an exception handler.
        If `fallthrough` is true, then return if the address is part of the fall-through case for a handler.
        If `filter` or `finally` is true, then return if the address is part of an SEH filter or SEH finalizer (respectively).
        """
        if not hasattr(idaapi, 'TBEA_ANY'):
            logging.fatal(u"{:s}.is_exception({:s}{:s}) : Support for interacting with exceptions is not available in your version ({:.1f}) of the IDA Pro disassembler (requires {:.1f}).".format('.'.join([__name__, cls.__name__]), "{:#x}".format(ea) if isinstance(ea, six.integer_types) else ea, u", {:s}".format(utils.string.kwargs(flags)) if flags else '', idaapi.__version__, 7.7))
            return cls.is_exception(ea, 0)

        tryflags = flags.pop('flags', 0) if flags else idaapi.TBEA_ANY

        # pre-assign some keyword args that we will map into actual flags.
        default = {
            'guard': idaapi.TBEA_TRY | idaapi.TBEA_SEHTRY, 'guarded': idaapi.TBEA_TRY | idaapi.TBEA_SEHTRY, 'try': idaapi.TBEA_TRY | idaapi.TBEA_SEHTRY,
            'handler': idaapi.TBEA_CATCH | idaapi.TBEA_SEHFILT, 'catch': idaapi.TBEA_CATCH | idaapi.TBEA_SEHFILT,
            'fall': idaapi.TBEA_FALLTHRU, 'fallthrough': idaapi.TBEA_FALLTHRU, 'fallthru': idaapi.TBEA_FALLTHRU,
        }

        # first comes the c++ keywords which are pretty minimalistic.
        try_kwargs = {
            'guard': idaapi.TBEA_TRY, 'guarded': idaapi.TBEA_TRY, 'try': idaapi.TBEA_TRY,
            'handler': idaapi.TBEA_CATCH, 'catch': idaapi.TBEA_CATCH,
        }

        # now do the same for seh keywords. we do these separately so we can
        # choose to either combine both try/seh or not.
        seh_kwargs = {
            'guard': idaapi.TBEA_SEHTRY, 'guarded': idaapi.TBEA_SEHTRY, 'try': idaapi.TBEA_SEHTRY,
            'filter': idaapi.TBEA_SEHFILT,
            'handler': idaapi.TBEA_CATCH, 'catch': idaapi.TBEA_CATCH,
            'finalizer': idaapi.TBEA_SEHLPAD, 'finally': idaapi.TBEA_SEHLPAD, 'final': idaapi.TBEA_SEHLPAD,
        }

        # and now a union...for the user that wants it all. we default with seh because
        # usually that's the thing people know first when they have no idea what they want.
        indecisive = {k : v for k, v in default.items()}
        [ indecisive.setdefault(k, v) for k, v in itertools.chain(*map(operator.methodcaller('items'), [seh_kwargs, try_kwargs])) ]

        # god i hope that ida doesn't add any more exception types or i might need to
        # wield science and turn this crap into a decision tree...
        try_choices = {flags.pop(key, False) for key in {'c++', 'cpp'} if operator.contains(flags, key)}
        seh_choices = {flags.pop(key, False) for key in {'seh', 'eh'} if operator.contains(flags, key)}

        explicit = try_explicit, seh_explicit = ((any(choices) if choices else None) for choices in [try_choices, seh_choices])
        kwargs = indecisive if all(explicit) else default if all(choices is None for choices in explicit) else [try_kwargs, seh_kwargs][0 if try_explicit else 1]

        # now we iterate through the kwargs and figure out what flags they wanted.
        tryflags, userflags = tryflags, {kw : value for kw, value in flags.items()}
        for key in flags:
            if not any(operator.contains(args, key) for args in [kwargs, default]):
                continue

            choice, value = userflags.pop(key), kwargs.get(key, default.get(key, 0))
            Fchoice = functools.partial(operator.or_, value) if choice else functools.partial(operator.and_, ~value)
            tryflags = idaapi.BADADDR & Fchoice(tryflags)

        # figure out if there were any flags that we couldn't interpret and warn the user about it.
        if userflags:
            leftover = sorted(userflags)
            logging.warning(u"{:s}.is_exception({:s}{:s}) : Ignored {:d} unknown parameter{:s} that {:s} passed as flags ({:s}).".format('.'.join([__name__, cls.__name__]), "{:#x}".format(ea) if isinstance(ea, six.integer_types) else ea, ", {:s}".format(utils.string.kwargs(flags)) if flags else '', len(leftover), '' if len(leftover) == 1 else 's', 'was' if len(leftover) == 1 else 'were', ', '.join(leftover)))

        # now we can get to the actual api.
        return cls.is_exception(ea, tryflags)
    @utils.multicase(ea=six.integer_types, flags=six.integer_types)
    @classmethod
    def is_exception(cls, ea, flags):
        '''Return if the address in `ea` is referenced by an exception matching the specified `flags` (``idaapi.TBEA_*``).'''
        is_ea_tryblks = idaapi.is_ea_tryblks if hasattr(idaapi, 'is_ea_tryblks') else utils.fconstant(False)
        return True if is_ea_tryblks(ea, flags) else False
    @utils.multicase(bounds=builtins.tuple, flags=six.integer_types)
    @classmethod
    def is_exception(cls, bounds, flags):
        '''Return if the given `bounds` is referenced by an exception matching the specified `flags` (``idaapi.TBEA_*``).'''
        return any(cls.is_exception(ea, flags) for ea in address.iterate(bounds))
    has_exception = isexception = hasexception = exceptionQ = utils.alias(is_exception, 'type')

t = type    # XXX: ns alias

class types(object):
    """
    This namespace is for interacting with the local types that are
    defined within the database. The functions within this namespace
    can be used to create, query, or fetch the types that have been
    defined.

    When listing the types that are matched, the following legend can be
    used to identify certain characteristics about them:

        `L` - The type originated from a type library
        `I` - The type originated from an inherited type library
        `T` - The type is a type definition and references another type
        `P` - The contents of the type is a pointer
        `F` - The contents of the type is a floating-point value (float, double, long double)
        `E` - The contents of the type is an enumeration
        `I` - The contents of the type is an integral
        `A` - The type represents an array
        `F` - The type represents a function
        `S` - The type represents a structure
        `V` - The type represents a virtual function table
        `C` - The type represents a structure containing a virtual function table
        `U` - The type represents a union
        `?` - The type is currently not defined

    The available types that one can filter the local types with are as follows:

        `ordinal` - Match according to the ordinal of the local type.
        `name` - Match according to the name of the local type.
        `like` - Filter the names of the local types according to a glob.
        `definition` - Filter the local types by applying a glob to their definition.
        `regex` - Filter the local types by applying a regular-expression to their definition.
        `typeref` or `typedef` - Filter the local types for any that are an alias declared with typedef.
        `defined` or `present` - Filter the local types for any that are defined.
        `size` - Filter the local types according to their size.
        `greater` or `ge` - Filter the local types for the ones that are larger or equal to a certain size.
        `gt` - Filter the local types for the ones that are larger than a certain size.
        `less` or `le` - Filter the local types for the ones that are less or equal to a certain size.
        `lt` - Filter the local types for the ones that are less than a certain size.
        `integer` - Filter the local types for any that are integers.
        `pointer` - Filter the local types for any that are pointers.
        `function` - Filter the local types for any that are functions.
        `float` - Filter the local types for any that are floating-point.
        `array` - Filter the local types for any that describe an array.
        `structure` - Filter the local types for any that describe a structure.
        `union` - Filter the local types for any that describe a union.
        `enumeration` - Filter the local types for any that describe an enumeration.
        `predicate` - Filter the types by passing their ordinal and ``idaapi.tinfo_t`` to a callable.

    Some examples of using these keywords are as follows::

        > database.types.list('*::*')
        > iterable = database.types.iterate(definition='*Cookie*')
        > result = database.types.search(regex='.*const.*')
    """

    @utils.multicase(library=idaapi.til_t)
    @classmethod
    def __formatter__(cls, library):
        lcls, description = library.__class__, library.desc
        return "<{:s}; <{:s}>>".format('.'.join([lcls.__module__, lcls.__name__]), utils.string.of(description))
    @utils.multicase(library=idaapi.til_t, ordinal=six.integer_types)
    @classmethod
    def __formatter__(cls, library, ordinal):
        ocls, name = idaapi.tinfo_t, idaapi.get_numbered_type_name(library, ordinal)
        if idaapi.get_type_ordinal(library, name) == ordinal:
            return "<{:s}; #{:d} \"{:s}\">".format('.'.join([lcls.__module__, lcls.__name__]), ordinal, utils.string.of(name))
        count = idaapi.get_ordinal_qty(library)
        if name is None:
            return "<{:s}; #{:s}>".format('.'.join([lcls.__module__, lcls.__name__]), "{:d}".format(ordinal) if 0 < ordinal < count else '???')
        return "<{:s}; #{:s} \"{:s}\">".format('.'.join([lcls.__module__, lcls.__name__]), "{:d}".format(ordinal) if 0 < ordinal < count else '???', name)
    @utils.multicase(library=idaapi.til_t, name=six.string_types)
    @classmethod
    @utils.string.decorate_arguments('name')
    def __formatter__(cls, library, name):
        ocls, ordinal = idaapi.tinfo_t, idaapi.get_type_ordinal(library, utils.string.to(name))
        return "<{:s}; #{:s} \"{:s}\">".format('.'.join([lcls.__module__, lcls.__name__]), "{:d}".format(ordinal) if ordinal else '???', name)

    __matcher__ = utils.matcher()
    __matcher__.boolean('name', lambda name, item: name.lower() == item.lower(), operator.itemgetter(1))
    __matcher__.combinator('like', utils.fcompose(fnmatch.translate, utils.fpartial(re.compile, flags=re.IGNORECASE), operator.attrgetter('match')), operator.itemgetter(1))
    __matcher__.predicate('predicate'), __matcher__.predicate('pred')
    __matcher__.boolean('ordinal', operator.eq, operator.itemgetter(0)), __matcher__.boolean('index', operator.eq, operator.itemgetter(0))
    __matcher__.combinator('definition', utils.fcompose(fnmatch.translate, utils.fpartial(re.compile, flags=re.IGNORECASE), operator.attrgetter('match')), operator.itemgetter(2), "{!s}".format)
    __matcher__.combinator('regex', utils.fcompose(utils.fpartial(re.compile, flags=re.IGNORECASE), operator.attrgetter('match')), operator.itemgetter(2), "{!s}".format)
    __matcher__.mapping('typeref', operator.truth, operator.itemgetter(2), operator.methodcaller('is_typeref'))
    __matcher__.mapping('typedef', operator.truth, operator.itemgetter(2), operator.methodcaller('is_typeref'))
    __matcher__.mapping('defined', operator.truth, operator.itemgetter(2), operator.methodcaller('present')), __matcher__.mapping('present', operator.truth, operator.itemgetter(2), operator.methodcaller('present'))

    __matcher__.mapping('integer', operator.truth, operator.itemgetter(2), operator.methodcaller('is_integral'))
    __matcher__.mapping('pointer', operator.truth, operator.itemgetter(2), operator.methodcaller('is_ptr'))
    __matcher__.mapping('function', operator.truth, operator.itemgetter(2), operator.methodcaller('is_func'))
    __matcher__.mapping('float', operator.truth, operator.itemgetter(2), operator.methodcaller('is_floating'))
    __matcher__.mapping('array', operator.truth, operator.itemgetter(2), operator.methodcaller('is_array'))
    __matcher__.mapping('structure', operator.truth, operator.itemgetter(2), operator.methodcaller('is_struct'))
    __matcher__.mapping('union', operator.truth, operator.itemgetter(2), operator.methodcaller('is_union'))
    __matcher__.mapping('enumeration', operator.truth, operator.itemgetter(2), operator.methodcaller('is_enum'))

    __matcher__.boolean('size', operator.eq, operator.itemgetter(2), operator.methodcaller('get_size'))
    __matcher__.boolean('greater', operator.le, operator.itemgetter(2), operator.methodcaller('get_size')), __matcher__.boolean('ge', operator.le, operator.itemgetter(2), operator.methodcaller('get_size'))
    __matcher__.boolean('gt', operator.lt, operator.itemgetter(2), operator.methodcaller('get_size')),
    __matcher__.boolean('less', operator.ge, operator.itemgetter(2), operator.methodcaller('get_size')), __matcher__.boolean('le', operator.ge, operator.itemgetter(2), operator.methodcaller('get_size'))
    __matcher__.boolean('lt', operator.gt, operator.itemgetter(2), operator.methodcaller('get_size'))

    @utils.multicase()
    @classmethod
    def __iterate__(cls):
        '''Iterates through all of the types in the current type library.'''
        til = idaapi.get_idati()
        return cls.__iterate__(til)
    @utils.multicase(library=idaapi.til_t)
    @classmethod
    def __iterate__(cls, library):
        '''Iterates through all of the types in the specified type `library`.'''
        count, errors = idaapi.get_ordinal_qty(library), {getattr(idaapi, name) : name for name in dir(idaapi) if name.startswith('sc_')}
        for ordinal in builtins.range(1, count):
            name, serialized = idaapi.get_numbered_type_name(library, ordinal), idaapi.get_numbered_type(library, ordinal)

            # if we didn't get any information returned, then this ordinal was deleted.
            if serialized is None:
                logging.warning(u"{:s}.__iterate__({:s}) : Skipping the type at the current ordinal ({:d}) due to it having been deleted.".format('.'.join([__name__, cls.__name__]), cls.__formatter__(library), ordinal))
                continue

            # try and create a new type from the serialized information. if we
            # fail at this, then this is a critical error.
            ti = cls.get(serialized, library)
            if ti is None:
                logging.fatal(u"{:s}.__iterate__({:s}) : Skipping the type at the current ordinal ({:d}) due to an error during deserialization.".format('.'.join([__name__, cls.__name__]), cls.__formatter__(library), ordinal))
                continue

            # if the type is empty, then we can just issue a warning and skip it.
            elif ti.empty():
                logging.warning(u"{:s}.__iterate__({:s}) : Skipping the type at the current ordinal ({:d}) due to it being empty.".format('.'.join([__name__, cls.__name__]), cls.__formatter__(library), ordinal))
                continue

            yield ordinal, utils.string.of(name or ''), ti
        return

    @utils.multicase(string=six.string_types)
    @classmethod
    @utils.string.decorate_arguments('string')
    def iterate(cls, string):
        '''Iterate through all of the types in current type library with a glob that matches `string`.'''
        til = idaapi.get_idati()
        return cls.iterate(til, like=string)
    @utils.multicase(string=six.string_types, library=idaapi.til_t)
    @classmethod
    @utils.string.decorate_arguments('string')
    def iterate(cls, string, library):
        '''Iterate through all of the types in the specified type `library` with a glob that matches `string`.'''
        return cls.iterate(library, like=string)
    @utils.multicase()
    @classmethod
    @utils.string.decorate_arguments('name', 'like', 'type', 'regex')
    def iterate(cls, **type):
        '''Iterate through all of the types in the current type library that match the keyword specified by `type`.'''
        til = idaapi.get_idati()
        return cls.iterate(til, **type)
    @utils.multicase(library=idaapi.til_t)
    @classmethod
    @utils.string.decorate_arguments('name', 'like', 'type', 'regex')
    def iterate(cls, library, **type):
        '''Iterate through all of the types in the specified type `library` that match the keyword specified by `type`.'''
        iterable = cls.__iterate__(library)
        for key, value in (type or {'predicate': utils.fconstant(True)}).items():
            iterable = cls.__matcher__.match(key, value, iterable)
        for item in iterable: yield item

    @utils.multicase(string=six.string_types)
    @classmethod
    @utils.string.decorate_arguments('string')
    def search(cls, string):
        '''Search through all of the type names in the current type library matching the glob `string` and return the first result.'''
        til = idaapi.get_idati()
        return cls.search(til, like=string)
    @utils.multicase(string=six.string_types, library=idaapi.til_t)
    @classmethod
    @utils.string.decorate_arguments('string')
    def search(cls, string, library):
        '''Search through all of the type names in the specified type `library` matching the glob `string` and return the first result.'''
        return cls.search(library, like=string)
    @utils.multicase()
    @classmethod
    @utils.string.decorate_arguments('name', 'like', 'type', 'regex')
    def search(cls, **type):
        '''Search through all of the types in the current type library that match the keyword specified by `type`.'''
        til = idaapi.get_idati()
        return cls.search(til, **type)
    @utils.multicase(library=idaapi.til_t)
    @classmethod
    @utils.string.decorate_arguments('name', 'like', 'type', 'regex')
    def search(cls, library, **type):
        '''Search through all of the types in the specified type `library` that match the keyword specified by `type`.'''
        query_s = utils.string.kwargs(type)

        listable = [item for item in cls.iterate(library, **type)]
        if len(listable) > 1:
            messages = ((u"[{:d}] {:+#x} {!s}".format(ordinal, ti.get_size() if ti.present() else 0, item)) for ordinal, item, ti in listable)
            [ logging.info(msg) for msg in messages ]
            ordinal, name, _ = listable[0]
            logging.warning(u"{:s}.search({:s}) : Found {:d} matching results. Returning the first type (#{:d}) \"{:s}\".".format('.'.join([__name__, cls.__name__]), query_s, len(listable), ordinal, utils.string.escape("{!s}".format(name), '"')))

        iterable = (ti for ordinal, name, ti in listable)
        res = builtins.next(iterable, None)
        if res is None:
            raise E.SearchResultsError(u"{:s}.search({:s}) : Found 0 matching results.".format('.'.join([__name__, cls.__name__]), query_s))
        return res

    @utils.multicase(string=six.string_types)
    @classmethod
    @utils.string.decorate_arguments('string')
    def list(cls, string):
        '''List all of the types in the current type library with a glob that matches `string`.'''
        til = idaapi.get_idati()
        return cls.list(til, like=string)
    @utils.multicase(string=six.string_types, library=idaapi.til_t)
    @classmethod
    @utils.string.decorate_arguments('string')
    def list(cls, string, library):
        '''List all of the types in the specified type `library` with a glob that matches `string`.'''
        return cls.list(library, like=string)
    @utils.multicase()
    @classmethod
    @utils.string.decorate_arguments('name', 'like', 'type', 'regex')
    def list(cls, **type):
        '''List all of the types in the specified type `library` that match the keyword specified by `type`.'''
        til = idaapi.get_idati()
        return cls.list(til, **type)
    @utils.multicase(library=idaapi.til_t)
    @classmethod
    @utils.string.decorate_arguments('name', 'like', 'type', 'regex')
    def list(cls, library, **type):
        '''List all of the types in the specified type `library` that match the keyword specified by `type`.'''
        ti = idaapi.tinfo_t()

        # Set some reasonable defaults for the list of types
        maxordinal = maxname = maxsize = 0

        # Perform the first pass through our listable grabbing all the lengths.
        listable = []
        for ordinal, name, ti in cls.iterate(library, **type):
            maxordinal = max(ordinal, maxordinal)
            maxname = max(len(name or ''), maxname)
            maxsize = max(ti.get_size(), maxsize)
            listable.append((ordinal, name, ti))

        # We just need to calculate the number of digits for the largest and size.
        cordinal = 2 + utils.string.digits(maxordinal, 10)
        csize = 2 + utils.string.digits(maxsize, 16)

        # Lookup table for figuring out some useful flags
        items = [
            ('T', 'is_typeref'),
        ]
        rlookup = [(q, operator.methodcaller(name)) for q, name in items if hasattr(ti, name)]

        items = [
            ('P', 'is_ptr'),
            ('F', 'is_floating'),
            ('E', 'is_enum'),
            ('I', 'is_integral'),
        ]
        ilookup = [(q, operator.methodcaller(name)) for q, name in items if hasattr(ti, name)]

        items = [
            ('A', 'is_array'),
            ('F', 'is_func'),
            ('V', 'is_vftable'),
            ('C', 'has_vftable'),
            ('S', 'is_struct'),
            ('U', 'is_union'),
        ]
        glookup = [(q, operator.methodcaller(name)) for q, name in items if hasattr(ti, name)]

        # Now we can list each type information located within the type library.
        for ordinal, name, ti in listable:

            # Apparently we can't use builtins.next because python is garbage.
            flibrary = '?' if not ti.present() else '-' if not ti.get_til() else 'I' if ti.is_from_subtil() else 'L'
            items = [q for q, F in rlookup if F(ti)]
            frtype = items[0] if items else '-'
            items = [q for q, F in ilookup if F(ti)]
            fitype = items[0] if items else '-'
            items = [q for q, F in glookup if F(ti)]
            fgtype = items[0] if items else '-'
            flags = itertools.chain(flibrary, frtype, fitype, fgtype)

            # That was it, now we can just display it.
            six.print_(u"{:<{:d}s} {:>+#{:d}x} : {:s} : {:<{:d}s}".format("[{:d}]".format(ordinal), cordinal, ti.get_size() if ti.present() else 0, 1 + csize, ''.join(flags), name, maxname))
        return

    @utils.multicase(ordinal=six.integer_types)
    @classmethod
    def by(cls, ordinal):
        '''Return the type information that is at the given `ordinal`.'''
        return cls.by_index(ordinal)
    @utils.multicase(name=six.string_types)
    @classmethod
    @utils.string.decorate_arguments('name')
    def by(cls, name):
        '''Return the type information that has the specified `name`.'''
        return cls.by_name(name)
    @utils.multicase(ordinal=six.integer_types, library=idaapi.til_t)
    @classmethod
    def by(cls, ordinal, library):
        '''Return the type information from the specified `library` that is at the given `ordinal`.'''
        return cls.by_index(ordinal, library)
    @utils.multicase(name=six.string_types, library=idaapi.til_t)
    @classmethod
    @utils.string.decorate_arguments('name')
    def by(cls, name, library):
        '''Return the type information from the specified `library` that is using the given `name`.'''
        return cls.by_name(name, library)

    @utils.multicase(ordinal=six.integer_types)
    @classmethod
    def has(cls, ordinal):
        '''Return whether the current type library has a type at the given `ordinal`.'''
        til = idaapi.get_idati()
        return cls.has(ordinal, til)
    @utils.multicase(name=six.string_types)
    @classmethod
    @utils.string.decorate_arguments('name')
    def has(cls, name):
        '''Return whether the current type library has a type with the specified `name`.'''
        til = idaapi.get_idati()
        return cls.has(name, til)
    @utils.multicase(ordinal=six.integer_types, library=idaapi.til_t)
    @classmethod
    def has(cls, ordinal, library):
        '''Return whether the provided type `library` has a type at the given `ordinal`.'''
        serialized = idaapi.get_numbered_type(library, ordinal)
        return True if serialized else False
    @utils.multicase(name=six.string_types, library=idaapi.til_t)
    @classmethod
    @utils.string.decorate_arguments('name')
    def has(cls, name, library):
        '''Return whether the provided type `library` has a type with the specified `name`.'''
        ordinal = idaapi.get_type_ordinal(library, utils.string.to(name))
        return True if ordinal else False

    @utils.multicase(name=six.string_types)
    @classmethod
    @utils.string.decorate_arguments('name')
    def by_name(cls, name):
        '''Return the type information that has the specified `name`.'''
        til = idaapi.get_idati()
        return cls.by_name(name, til)
    @utils.multicase(name=six.string_types, library=idaapi.til_t)
    @classmethod
    @utils.string.decorate_arguments('name')
    def by_name(cls, name, library):
        '''Return the type information from the specified `library` that is using the given `name`.'''
        ordinal = idaapi.get_type_ordinal(library, utils.string.to(name))
        if ordinal:
            return cls.by_index(ordinal, library)
        raise E.ItemNotFoundError(u"{:s}.by_name({!r}, {:s}) : No type information was found in the type library with the specified name (\"{:s}\").".format('.'.join([__name__, cls.__name__]), name, cls.__formatter__(library), utils.string.escape(name, '"')))

    @utils.multicase(ordinal=six.integer_types)
    @classmethod
    def by_index(cls, ordinal):
        '''Return the type information that is at the given `ordinal`.'''
        til = idaapi.get_idati()
        return cls.by_index(ordinal, til)
    @utils.multicase(ordinal=six.integer_types, library=idaapi.til_t)
    @classmethod
    def by_index(cls, ordinal, library):
        '''Return the type information from the specified `library` that is at the given `ordinal`.'''
        serialized = idaapi.get_numbered_type(library, ordinal)
        if serialized:
            return cls.get(serialized, library)
        raise E.ItemNotFoundError(u"{:s}.by_index({:d}, {:s}) : No type information was found in the type library for the specified ordinal ({:d}).".format('.'.join([__name__, cls.__name__]), ordinal, cls.__formatter__(library), ordinal))

    @utils.multicase(info=idaapi.tinfo_t)
    @classmethod
    def name(cls, info):
        '''Return the name of the type from the current type library that matches the given type `info`.'''
        til = idaapi.get_idati()
        return cls.name(info, til)
    @utils.multicase(ordinal=six.integer_types)
    @classmethod
    def name(cls, ordinal):
        '''Return the name of the type from the current type library at the specified `ordinal`.'''
        til = idaapi.get_idati()
        return cls.name(ordinal, til)
    @utils.multicase(info=idaapi.tinfo_t, library=idaapi.til_t)
    @classmethod
    def name(cls, info, library):
        '''Return the name of the type from the specified type `library` that matches the given type `info`.'''
        # FIXME: i seriously doubt that this is actually possible
        raise NotImplementedError
    @utils.multicase(ordinal=six.integer_types, library=idaapi.til_t)
    @classmethod
    def name(cls, ordinal, library):
        '''Return the name of the type from the specified type `library` at the given `ordinal`.'''
        res = idaapi.get_numbered_type_name(library, ordinal)
        if res is None:
            raise E.ItemNotFoundError(u"{:s}.name({:d}, {:s}) : Unable to return the name of specified ordinal ({:d}) from the type library.".format('.'.join([__name__, cls.__name__]), ordinal, cls.__formatter__(library), ordinal))
        # FIXME: which one do we get? the mangled or unmangled name?
        return utils.string.of(res)
    @utils.multicase(ordinal=six.integer_types, string=six.string_types)
    @classmethod
    @utils.string.decorate_arguments('string')
    def name(cls, ordinal, string, **mangled):
        '''Set the name of the type at the specified `ordinal` from the current library to `string`.'''
        til = idaapi.get_idati()
        return cls.name(ordinal, string, til, **mangled)
    @utils.multicase(ordinal=six.integer_types, string=six.string_types, library=idaapi.til_t)
    @classmethod
    @utils.string.decorate_arguments('string')
    def name(cls, ordinal, string, library, **mangled):
        """Set the name of the type at the specified `ordinal` of the given type `library` to `string`.

        If the boolean `mangled` is specified, then the given name is mangled.
        """
        name, ti = cls.name(ordinal, library), cls.get(ordinal, library)
        if ti is None:
            raise E.DisassemblerError(u"{:s}.name({:d}, {!r}, {:s}{:s}) : Unable to get the type information from the given ordinal ({:d}) of the type library.".format('.'.join([__name__, cls.__name__]), ordinal, string, cls.__formatter__(library), u", {:s}".format(utils.string.kwargs(mangled)) if mangled else '', ordinal))

        # now that we saved the type information, we can re-assign the type
        # and change the ordinal's name at the very same tie.
        res = cls.set(ordinal, utils.string.to(string), ti, library, **mangled)
        if ti.serialize() != res.serialize():
            logging.warning(u"{:s}.name({:d}, {!r}, {:s}{:s}) : The type information for the given ordinal ({:d}) applied the type library has changed during the assignment of the new name ({!r}).".format('.'.join([__name__, cls.__name__]), ordinal, string, cls.__formatter__(library), u", {:s}".format(utils.string.kwargs(mangled)) if mangled else '', ordinal, utils.string.of(string)))
        return name

    @utils.multicase(ordinal=six.integer_types)
    @classmethod
    def get(cls, ordinal):
        '''Get the type information at the given `ordinal` of the current type library and return it.'''
        til = idaapi.get_idati()
        return cls.get(ordinal, til)
    @utils.multicase(name=six.string_types)
    @classmethod
    @utils.string.decorate_arguments('name')
    def get(cls, name):
        '''Get the type information with the given `name` from the current type library and return it.'''
        til = idaapi.get_idati()
        return cls.get(name, til)
    @utils.multicase(ordinal=six.integer_types, library=idaapi.til_t)
    @classmethod
    def get(cls, ordinal, library):
        '''Get the type information at the given `ordinal` of the specified type `library` and return it.'''
        if 0 < ordinal < idaapi.get_ordinal_qty(library):
            serialized = idaapi.get_numbered_type(library, ordinal)
            if serialized is not None:
                return cls.get(serialized, library)
        raise E.ItemNotFoundError(u"{:s}.get({:d}, {:s}) : No type information was found for the specified ordinal ({:d}) in the type library.".format('.'.join([__name__, cls.__name__]), ordinal, cls.__formatter__(library), ordinal))
    @utils.multicase(name=six.string_types, library=idaapi.til_t)
    @classmethod
    @utils.string.decorate_arguments('name')
    def get(cls, name, library):
        '''Get the type information with the given `name` from the specified type `library` and return it.'''
        ordinal = idaapi.get_type_ordinal(library, utils.string.to(name))
        if ordinal:
            return cls.get(ordinal, library)
        raise E.ItemNotFoundError(u"{:s}.get({!r}, {:s}) : No type information with the specified name (\"{:s}\") was found in the type library.".format('.'.join([__name__, cls.__name__]), name, cls.__formatter__(library), utils.string.escape(name, '"')))

    # The following cases for the "types.get" functon are actually a lie and
    # only exist as a way to get an "idaapi.tinfo_t" from any IDAPython API
    # that returns the information in its serialized form.

    @utils.multicase(serialized=builtins.tuple)
    @classmethod
    def get(cls, serialized):
        '''Convert the `serialized` type information from the current type library and return it.'''
        til = idaapi.get_idati()
        return cls.get(serialized, til)
    @utils.multicase(serialized=builtins.tuple, library=idaapi.til_t)
    @classmethod
    def get(cls, serialized, library):
        '''Convert the `serialized` type information from the specified type `library` and return it.'''
        type, fields, cmt, fieldcmts, sclass = itertools.chain(serialized, [b'', getattr(idaapi, 'sc_unk', 0)][len(serialized) - 5:] if len(serialized) < 5 else [])

        # ugh..because ida can return a non-bytes as one of the comments, we
        # need to convert it so that the api will fucking understand us.
        res = cmt or fieldcmts or b''
        comments = res if isinstance(res, bytes) else res.encode('latin1')

        # we need to generate a description so that we can format error messages the user will understand.
        errors = {getattr(idaapi, name) : name for name in dir(idaapi) if name.startswith('sc_')}
        names = ['type', 'fields', 'cmt', 'fieldcmts']

        items = itertools.chain(["{:s}={!r}".format(name, item) for name, item in zip(names, serialized) if item], ["{:s}={!s}".format('sclass', sclass)] if len(serialized) == 5 else [])
        description = [item for item in items]

        # try and deserialize the type information. if we succeeded then we
        # can actually return the damned thing.
        ti = idaapi.tinfo_t()
        if ti.deserialize(library, type, fields, comments):
            return ti

        # if we were unable to do that, then we need to log a critical error
        # that's somewhat useful before returning None back to the user.
        logging.fatal(u"{:s}.get({:s}{:s}) : Unable to deserialize the type information for a type using the returned storage class {:s}.".format('.'.join([__name__, cls.__name__]), cls.__formatter__(library), ", {:s}".format(', '.join(description)) if description else '', "{:s}({:d})".format(errors[sclass], sclass) if sclass in errors else "({:d})".format(sclass)))
        return

    @utils.multicase(ordinal=six.integer_types, info=(six.string_types, idaapi.tinfo_t))
    @classmethod
    def set(cls, ordinal, info):
        '''Assign the type information `info` to the type at the specified `ordinal` of the current type library.'''
        til = idaapi.get_idati()
        return cls.set(ordinal, info, til)
    @utils.multicase(ordinal=six.integer_types, name=six.string_types, info=(six.string_types, idaapi.tinfo_t))
    @classmethod
    @utils.string.decorate_arguments('name')
    def set(cls, ordinal, name, info, **mangled):
        '''Assign the type information `info` with the specified `name` to the given `ordinal` of the current type library.'''
        til = idaapi.get_idati()
        return cls.set(ordinal, name, info, til, **mangled)
    @utils.multicase(ordinal=six.integer_types, info=(six.string_types, idaapi.tinfo_t), library=idaapi.til_t)
    @classmethod
    def set(cls, ordinal, info, library):
        '''Assign the type information `info` to the type at the `ordinal` of the specified type `library`.'''
        try:
            # FIXME: do we get the mangled or unmangled name?
            name = cls.name(ordinal, library)

        except Exception:
            # FIXME: if we couldn't find a name, can we create one based on the ordinal number (is_ordinal_name)?
            raise E.MissingNameError(u"{:s}.set({:d}, {!r}, {:s}) : Unable to assign the type information to the specified ordinal ({:d}) because it needs a name and a previous one was not found.".format('.'.join([__name__, cls.__name__]), ordinal, "{!s}".format(info), cls.__formatter__(library), ordinal))
        return cls.set(ordinal, name, info, library)
    @utils.multicase(ordinal=six.integer_types, name=six.string_types, string=six.string_types, library=idaapi.til_t)
    @classmethod
    @utils.string.decorate_arguments('name', 'string')
    def set(cls, ordinal, name, string, library, **mangled):
        '''Assign the type information in `string` with the specified `name` to the specified `ordinal` of the given type `library`.'''
        ti = internal.declaration.parse(string)
        if ti is None:
            raise E.InvalidTypeOrValueError(u"{:s}.set({:d}, {!r}, {!r}, {:s}{:s}) : Unable to parse the specified type declaration ({!s}).".format('.'.join([__name__, cls.__name__]), ordinal, name, string, cls.__formatter__(library), ", {:s}".format(utils.string.kwargs(mangled)) if mangled else '', utils.string.repr(string)))
        return cls.set(ordinal, name, ti, library, **mangled)
    @utils.multicase(ordinal=six.integer_types, name=six.string_types, info=idaapi.tinfo_t, library=idaapi.til_t)
    @classmethod
    @utils.string.decorate_arguments('name')
    def set(cls, ordinal, name, info, library, **mangled):
        """Assign the type information `info` with the specified `name` to the given `ordinal` of the type `library`.

        If the boolean `mangled` is specified, then the given name is mangled.
        """
        errors = {getattr(idaapi, name) : name for name in dir(idaapi) if name.startswith('TERR_')}

        # first try to get the type information at the given ordinal so that we can return it.
        try:
            ti = cls.get(ordinal, library)
        except Exception:
            ti = None

        # serialize the type information that we're being asked to assign.
        serialized = info.serialize()
        if serialized is None:
            raise E.DisassemblerError(u"{:s}.set({:d}, {!r}, {!r}, {:s}{:s}) : Unable to serialize the given type information to assign to the ordinal ({:d}) of the type library.".format('.'.join([__name__, cls.__name__]), ordinal, name, "{!s}".format(info), cls.__formatter__(library), u", {:s}".format(utils.string.kwargs(mangled)) if mangled else '', ordinal))

        # we aren't given all of the necessary parameters for set_numbered_type,
        # so we assign some defaults so we can actually set it.
        type, fields, fieldcmts = serialized
        cmt, sclass, fieldcmts = b'', idaapi.sc_unk, fieldcmts or b''

        # set the default flags that we're going to use when using set_numbered_type.
        flags = mangled.get('flags', idaapi.NTF_CHKSYNC)
        flags |= idaapi.NTF_SYMM if mangled.get('mangled', False) else idaapi.NTF_SYMU

        # now we need to actually validate the name that we were given. IDA's names
        # handle the first character differently (like an identifier), so we need
        # to check that first before we figure out the rest of them.
        iterable = (item for item in name)
        item = builtins.next(iterable, '_')
        identifier = item if idaapi.is_valid_typename(utils.string.to(item)) else '_'
        identifier+= str().join(item if idaapi.is_valid_typename(identifier + utils.string.to(item)) else '_' for item in iterable)

        # we need to now assign the serialized data we were given, making sure
        # that any of the any of the comments are properly being passed as bytes
        # and then we can check to see if it returned an error.
        res = idaapi.set_numbered_type(library, ordinal, idaapi.NTF_REPLACE | flags, utils.string.to(identifier), type, fields, cmt.decode('latin1') if isinstance(cmt, bytes) else cmt, fieldcmts if isinstance(fieldcmts, bytes) else fieldcmts.encode('latin1'), sclass)
        if res == idaapi.TERR_WRONGNAME:
            raise E.DisassemblerError(u"{:s}.set({:d}, {!r}, {!r}, {:s}) : Unable to set the type information for the ordinal ({:d}) in the type library with the given name ({!r}) due to error {:s}.".format('.'.join([__name__, cls.__name__]), ordinal, name, "{!s}".format(info), cls.__formatter__(library), ordinal, identifier, "{:s}({:d})".format(errors[res], res) if res in errors else "code ({:d})".format(res)))
        elif res != idaapi.TERR_OK:
            raise E.DisassemblerError(u"{:s}.set({:d}, {!r}, {!r}, {:s}) : Unable to set the type information for the ordinal ({:d}) in the specified type library due to error {:s}.".format('.'.join([__name__, cls.__name__]), ordinal, name, "{!s}".format(info), cls.__formatter__(library), ordinal, "{:s}({:d})".format(errors[res], res) if res in errors else "code ({:d})".format(res)))
        return ti

    @utils.multicase(ordinal=six.integer_types)
    @classmethod
    def remove(cls, ordinal):
        '''Remove the type information at the specified `ordinal` of the current type library.'''
        til = idaapi.get_idati()
        return cls.remove(ordinal, til)
    @utils.multicase(ordinal=six.integer_types, library=idaapi.til_t)
    @classmethod
    def remove(cls, ordinal, library):
        '''Remove the type information at the `ordinal` of the specified type `library`.'''
        res = cls.get(ordinal, library)
        if not idaapi.del_numbered_type(library, ordinal):
            raise E.ItemNotFoundError(u"{:s}.remove({:d}, {:s}) : Unable to delete the type information at the specified ordinal ({:d}) of the type library.".format('.'.join([__name__, cls.__name__]), ordinal, cls.__formatter__(library), ordinal))
        return res
    @utils.multicase(name=six.string_types)
    @classmethod
    @utils.string.decorate_arguments('name')
    def remove(cls, name, **mangled):
        '''Remove the type information with the specified `name` from the current type library.'''
        til = idaapi.get_idati()
        return cls.remove(name, til, **mangled)
    @utils.multicase(name=six.string_types, library=idaapi.til_t)
    @classmethod
    @utils.string.decorate_arguments('name')
    def remove(cls, name, library, **mangled):
        """Remove the type information with the specified `name` from the specified type `library`.

        If the boolean `mangled` is specified, then the given name is mangled.
        """
        res = cls.get(ordinal, library)

        # we need to figure out what flags to use from the keyword parameters.
        flags = mangled.get('flags', 0)
        flags |= idaapi.NTF_SYMM if mangled.get('mangled', False) else idaapi.NTF_SYMU

        # now we can actually try using del_named_type with our given name and flags.
        if not idaapi.del_named_type(library, utils.string.to(name), idaapi.NTF_TYPE | flags):
            raise E.ItemNotFoundError(u"{:s}.remove({!r}, {:s}{:s}) : Unable to delete the type information with the specified name (\"{:s}\") from the type library.".format('.'.join([__name__, cls.__name__]), name, cls.__formatter__(library), u", {:s}".format(utils.string.kwargs(mangled)) if mangled else '', utils.string.escape(name, '"')))
        return res

    @utils.multicase(name=six.string_types)
    @classmethod
    @utils.string.decorate_arguments('name')
    def add(cls, name, **mangled):
        '''Add an empty type with the provided `name` to the current type library.'''
        til = idaapi.get_idati()
        return cls.add(name, til, **mangled)
    @utils.multicase(name=six.string_types, library=idaapi.til_t)
    @classmethod
    @utils.string.decorate_arguments('name')
    def add(cls, name, library, **mangled):
        '''Add an empty type with the provided `name` to the specified type `library`.'''
        ti = cls.parse(' '.join(['struct', name]))
        return cls.add(name, ti, library, **mangled)
    @utils.multicase(name=six.string_types, info=(six.string_types, idaapi.tinfo_t))
    @classmethod
    @utils.string.decorate_arguments('name')
    def add(cls, name, info, **mangled):
        '''Add the type information in `info` to the current type library using the provided `name`.'''
        til = idaapi.get_idati()
        return cls.add(name, info, til, **mangled)
    @utils.multicase(name=six.string_types, string=six.string_types, library=idaapi.til_t)
    @classmethod
    @utils.string.decorate_arguments('name')
    def add(cls, name, string, library, **mangled):
        '''Add the type information in `string` to the specified type `library` using the provided `name`.'''
        ti = internal.declaration.parse(string)
        if ti is None:
            raise E.InvalidTypeOrValueError(u"{:s}.add({!r}, {!r}, {:s}{:s}) : Unable to parse the specified type declaration ({:s}).".format('.'.join([__name__, cls.__name__]), name, string, cls.__formatter__(library), ", {:s}".format(utils.string.kwargs(mangled)) if mangled else '', utils.string.repr(string)))
        return cls.add(name, ti, library, **mangled)
    @utils.multicase(name=six.string_types, info=idaapi.tinfo_t, library=idaapi.til_t)
    @classmethod
    @utils.string.decorate_arguments('name')
    def add(cls, name, info, library, **mangled):
        """Add the type information in `info` to the specified type `library` using the provided `name`.

        If the boolean `mangled` is specified, then the given name is mangled.
        """
        errors = {getattr(idaapi, name) : name for name in dir(idaapi) if name.startswith('TERR_')}

        # first we'll try to serialize the type before we make any perma-changes.
        serialized = info.serialize()
        if serialized is None:
            raise E.DisassemblerError(u"{:s}.add({!r}, {!r}, {:s}{:s}) : Unable to serialize the type information that will be added to the type library.".format('.'.join([__name__, cls.__name__]), name, "{!s}".format(info), cls.__formatter__(library), u", {:s}".format(utils.string.kwargs(mangled)) if mangled else ''))

        # serialization does not give us all of the parameters required to actually
        # use set_numbered_type, so we assign some defaults to use.
        type, fields, fieldcmts = serialized
        cmt, sclass, fieldcmts = b'', idaapi.sc_unk, fieldcmts or b''

        # now we can allocate a slot for the ordinal within the type library.
        ordinal = idaapi.alloc_type_ordinals(library, 1)
        if not ordinal:
            raise E.DisassemblerError(u"{:s}.add({!r}, {!r}, {:s}{:s}) : Unable to allocate an ordinal within the specified type library.".format('.'.join([__name__, cls.__name__]), name, "{!s}".format(info), cls.__formatter__(library), u", {:s}".format(utils.string.kwargs(mangled)) if mangled else ''))

        # set the default flags that we're going to use when using set_numbered_type.
        flags = mangled.get('flags', idaapi.NTF_CHKSYNC | idaapi.NTF_TYPE)
        flags |= idaapi.NTF_SYMM if mangled.get('mangled', False) else idaapi.NTF_SYMU

        # last thing we need to do is correct the name we were given to a valid one
        # since IDA wants these to follow the format (character set) for a general C
        # identifier. so we'll simply do the first character, then finish the rest.
        iterable = (item for item in name)
        item = builtins.next(iterable, '_')
        identifier = item if idaapi.is_valid_typename(utils.string.to(item)) else '_'
        identifier+= str().join(item if idaapi.is_valid_typename(identifier + utils.string.to(item)) else '_' for item in iterable)

        # we can now assign the serialized data that we got, making sure that
        # the comments are properly being passed as bytes before checking for error.
        res = idaapi.set_numbered_type(library, ordinal, flags, utils.string.to(identifier), type, fields, cmt.decode('latin1') if isinstance(cmt, bytes) else cmt, fieldcmts if isinstance(fieldcmts, bytes) else fieldcmts.encode('latin1'), sclass)
        if res == idaapi.TERR_OK:
            return ordinal

        # if we got an error, then we need to delete the ordinal we just added
        # and then we can just raise an exception for the user to deal with.
        if not idaapi.del_numbered_type(library, ordinal):
            logging.fatal(u"{:s}.add({!r}, {!r}, {:s}{:s}) : Unable to delete the recently added ordinal ({:d}) from the specified type library.".format('.'.join([__name__, cls.__name__]), name, info, cls.__formatter__(library), u", {:s}".format(utils.string.kwargs(mangled)) if mangled else '', ordinal))

        # now we can check the error code and fail properly with an exception.
        if res == idaapi.TERR_WRONGNAME:
            raise E.DisassemblerError(u"{:s}.add({!r}, {!r}, {:s}{:s}) : Unable to add the type information to the type library at the allocated ordinal ({:d}) with the given name ({!r}) due to error {:s}.".format('.'.join([__name__, cls.__name__]), name, "{!s}".format(info), cls.__formatter__(library), u", {:s}".format(utils.string.kwargs(mangled)) if mangled else '', ordinal, identifier, "{:s}({:d})".format(errors[res], res) if res in errors else "code ({:d})".format(res)))
        raise E.DisassemblerError(u"{:s}.add({!r}, {!r}, {:s}{:s}) : Unable to add the type information to the type library at the allocated ordinal ({:d}) due to error {:s}.".format('.'.join([__name__, cls.__name__]), name, "{!s}".format(info), cls.__formatter__(library), u", {:s}".format(utils.string.kwargs(mangled)) if mangled else '', ordinal, "{:s}({:d})".format(errors[res], res) if res in errors else "code ({:d})".format(res)))

    @utils.multicase()
    @classmethod
    def count(cls):
        '''Return the number of types that are available in the current type library.'''
        til = idaapi.get_idati()
        return cls.count(til)
    @utils.multicase(library=idaapi.til_t)
    @classmethod
    def count(cls, library):
        '''Return the number of types that are available in the specified type `library`.'''
        return idaapi.get_ordinal_qty(library)

    @utils.multicase(string=six.string_types)
    @classmethod
    def declare(cls, string, **flags):
        '''Parse the given `string` into an ``idaapi.tinfo_t`` using the current type library and return it.'''
        til = idaapi.cvar.idati if idaapi.__version__ < 7.0 else idaapi.get_idati()
        return cls.parse(string, til, **flags)
    @utils.multicase(string=six.string_types, library=idaapi.til_t)
    @classmethod
    def declare(cls, string, library, **flags):
        """Parse the given `string` into an ``idaapi.tinfo_t`` using the specified type `library` and return it.

        If the integer `flags` is provided, then use the specified flags (``idaapi.PT_*``) when parsing the `string`.
        """
        ti, flag = idaapi.tinfo_t(), flags.get('flags', idaapi.PT_SIL | idaapi.PT_TYP)

        # Firstly we need to ';'-terminate the type the user provided in order
        # for IDA's parser to understand it.
        terminated = string if string.endswith(';') else "{:s};".format(string)

        # Ask IDA to parse this into a tinfo_t for us. We default to the silent flag
        # so that we're responsible for handling it if there's a parsing error of
        # some sort. If it succeeds, then we can return our typeinfo otherwise we'll
        # return None to avoid returning a completely invalid type.
        if idaapi.__version__ < 6.9:
            ok, name = idaapi.parse_decl2(library, terminated, None, ti, flag), None
        elif idaapi.__version__ < 7.0:
            ok, name = idaapi.parse_decl2(library, terminated, ti, flag), None
        else:
            name = idaapi.parse_decl(ti, library, terminated, flag)
            ok = name is not None

        # If we couldn't parse the type we were given, then simply bail.
        if not ok:
            raise E.DisassemblerError(u"{:s}.declare({!r}, {:s}{:s}) : Unable to parse the provided string into a valid type.".format('.'.join([__name__, cls.__name__]), string, cls.__formatter__(library), u", {:s}".format(utils.string.kwargs(flags)) if flags else ''))

        # If we were given the idaapi.PT_VAR flag, then we return the parsed name too.
        logging.info(u"{:s}.declare({!r}, {:s}{:s}) : Successfully parsed the given string into a valid type{:s}.".format('.'.join([__name__, cls.__name__]), string, cls.__formatter__(library), u", {:s}".format(utils.string.kwargs(flags)) if flags else '', " ({:s})".format(name) if name else ''))
        return (name, ti) if flag & idaapi.PT_VAR else ti
    parse = decl = utils.alias(declare, 'types')

## information about a given address
size = utils.alias(type.size, 'type')
is_code = utils.alias(type.is_code, 'type')
is_data = utils.alias(type.is_data, 'type')
is_unknown = utils.alias(type.is_unknown, 'type')
is_head = utils.alias(type.is_head, 'type')
is_tail = utils.alias(type.is_tail, 'type')
is_align = utils.alias(type.is_align, 'type')

class xref(object):
    """
    This namespace is for navigating the cross-references (xrefs)
    associated with an address in the database. This lets one identify
    code xrefs from data xrefs and even allows one to add or remove
    xrefs as they see fit.

    This namespace is also aliased as ``database.x``.

    Some of the more common functions are used so often that they're
    also aliased as globals. Some of these are:

        ``database.up`` - Return all addresses that reference an address
        ``database.down`` - Return all addresses that an address references
        ``database.drefs`` - Return all the data references for an address
        ``database.crefs`` - Return all the code references for an address
        ``database.dxup`` - Return all the data references that reference an address
        ``database.dxdown`` - Return all the data references that an address references
        ``database.cxup`` - Return all the code references that reference an address
        ``database.cxdown`` - Return all the code references that an address references

    Some ways to utilize this namespace can be::

        > print( database.x.up() )
        > for ea in database.x.down(): ...
        > for ea in database.x.cu(ea): ...
        > ok = database.x.add_code(ea, target)
        > ok = database.x.rm_data(ea)

    """

    @utils.multicase()
    @staticmethod
    def code():
        '''Return all of the code xrefs that refer to the current address.'''
        return xref.code(ui.current.address(), False)
    @utils.multicase(descend=bool)
    @staticmethod
    def code(descend):
        return xref.code(ui.current.address(), descend)
    @utils.multicase(ea=six.integer_types)
    @staticmethod
    def code(ea):
        '''Return all of the code xrefs that refer to the address `ea`.'''
        return xref.code(ea, False)
    @utils.multicase(ea=six.integer_types, descend=bool)
    @staticmethod
    def code(ea, descend):
        """Return all of the code xrefs that refer to the address `ea`.

        If the bool `descend` is defined, then return only code refs that are referred by the specified address.
        """
        if descend:
            start, next = idaapi.get_first_cref_from, idaapi.get_next_cref_from
        else:
            start, next = idaapi.get_first_cref_to, idaapi.get_next_cref_to

        ea = interface.address.inside(ea)
        for addr in interface.xiterate(ea, start, next):
            yield addr
        return
    c = utils.alias(code, 'xref')

    @utils.multicase()
    @staticmethod
    def data():
        '''Return all of the data xrefs that refer to the current address.'''
        return xref.data(ui.current.address(), False)
    @utils.multicase(descend=bool)
    @staticmethod
    def data(descend):
        return xref.data(ui.current.address(), descend)
    @utils.multicase(ea=six.integer_types)
    @staticmethod
    def data(ea):
        '''Return all of the data xrefs that refer to the address `ea`.'''
        return xref.data(ea, False)
    @utils.multicase(ea=six.integer_types, descend=bool)
    @staticmethod
    def data(ea, descend):
        """Return all of the data xrefs that refer to the address `ea`.

        If the bool `descend` is defined, then return only the data refs that are referred by the specified address.
        """
        if descend:
            start, next = idaapi.get_first_dref_from, idaapi.get_next_dref_from
        else:
            start, next = idaapi.get_first_dref_to, idaapi.get_next_dref_to

        ea = interface.address.inside(ea)
        for addr in interface.xiterate(ea, start, next):
            yield addr
        return
    d = utils.alias(data, 'xref')

    @utils.multicase()
    @staticmethod
    def data_down():
        '''Return all of the data xrefs that are referenced by the current address.'''
        return xref.data_down(ui.current.address())
    @utils.multicase(ea=six.integer_types)
    @staticmethod
    def data_down(ea):
        '''Return all of the data xrefs that are referenced by the address `ea`.'''
        return sorted(xref.data(ea, True))
    dd = utils.alias(data_down, 'xref')

    @utils.multicase()
    @staticmethod
    def data_up():
        '''Return all of the data xrefs that refer to the current address.'''
        return xref.data_up(ui.current.address())
    @utils.multicase(ea=six.integer_types)
    @staticmethod
    def data_up(ea):
        '''Return all of the data xrefs that refer to the address `ea`.'''
        return sorted(xref.data(ea, False))
    du = utils.alias(data_up, 'xref')

    @utils.multicase()
    @staticmethod
    def code_down():
        '''Return all of the code xrefs that are referenced by the current address.'''
        return xref.code_down(ui.current.address())
    @utils.multicase(ea=six.integer_types)
    @staticmethod
    def code_down(ea):
        '''Return all of the code xrefs that are referenced by the address `ea`.'''
        res = {item for item in xref.code(ea, True)}

        # if we're not pointing at code, then the logic that follows is irrelevant
        if not type.is_code(ea):
            return sorted(res)

        try:
            # try and grab the next instruction which might be referenced
            next_ea = address.next(ea)

            # if the current instruction is a non-"stop" instruction, then it will
            # include a reference to the next instruction. so, we'll remove it.
            if type.is_code(ea) and _instruction.type.feature(ea, idaapi.CF_STOP) != idaapi.CF_STOP:
                res.discard(next_ea)

        except E.OutOfBoundsError:
            pass

        return sorted(res)
    cd = utils.alias(code_down, 'xref')

    @utils.multicase()
    @staticmethod
    def code_up():
        '''Return all of the code xrefs that are referenced by the current address.'''
        return xref.code_up(ui.current.address())
    @utils.multicase(ea=six.integer_types)
    @staticmethod
    def code_up(ea):
        '''Return all of the code xrefs that refer to the address `ea`.'''
        res = {item for item in xref.code(ea, False)}

        # if we're not pointing at code, then the logic that follows is irrelevant
        if not type.is_code(ea):
            return sorted(res)

        try:
            # try and grab the previous instruction which be referenced
            prev_ea = address.prev(ea)

            # if the previous instruction is a non-"stop" instruction, then it will
            # reference the current instruction which is a reason to remove it.
            if type.is_code(prev_ea) and _instruction.type.feature(prev_ea, idaapi.CF_STOP) != idaapi.CF_STOP:
                res.discard(prev_ea)

        except E.OutOfBoundsError:
            pass

        return sorted(res)
    cu = utils.alias(code_up, 'xref')

    @utils.multicase()
    @staticmethod
    def up():
        '''Return all of the references that refer to the current address.'''
        return xref.up(ui.current.address())
    @utils.multicase(ea=six.integer_types)
    @staticmethod
    def up(ea):
        '''Return all of the references that refer to the address `ea`.'''
        code, data = {item for item in xref.code_up(ea)}, {item for item in xref.data_up(ea)}
        return sorted(code | data)
    u = utils.alias(up, 'xref')

    # All locations that are referenced by the specified address
    @utils.multicase()
    @staticmethod
    def down():
        '''Return all of the references that are referred by the current address.'''
        return xref.down(ui.current.address())
    @utils.multicase(ea=six.integer_types)
    @staticmethod
    def down(ea):
        '''Return all of the references that are referred by the address `ea`.'''
        code, data = {item for item in xref.code_down(ea)}, {item for item in xref.data_down(ea)}
        return sorted(code | data)
    d = utils.alias(down, 'xref')

    @utils.multicase(target=six.integer_types)
    @staticmethod
    def add_code(target, **reftype):
        '''Add a code reference from the current address to `target`.'''
        return xref.add_code(ui.current.address(), target, **reftype)
    @utils.multicase(ea=six.integer_types, target=six.integer_types)
    @staticmethod
    def add_code(ea, target, **reftype):
        """Add a code reference from address `ea` to `target`.

        If the reftype `call` is true, then specify this ref as a function call.
        """
        ea, target = interface.address.head(ea, target)

        isCall = builtins.next((reftype[k] for k in ['call', 'is_call', 'isCall', 'iscall', 'callQ'] if k in reftype), None)
        if abs(target - ea) > pow(2, config.bits() // 2):
            flowtype = idaapi.fl_CF if isCall else idaapi.fl_JF
        else:
            flowtype = idaapi.fl_CN if isCall else idaapi.fl_JN
        idaapi.add_cref(ea, target, flowtype | idaapi.XREF_USER)
        return target in xref.code_down(ea)
    ac = utils.alias(add_code, 'xref')

    @utils.multicase(target=six.integer_types)
    @staticmethod
    def add_data(target, **reftype):
        '''Add a data reference from the current address to `target`.'''
        return xref.add_data(ui.current.address(), target, **reftype)
    @utils.multicase(ea=six.integer_types, target=six.integer_types)
    @staticmethod
    def add_data(ea, target, **reftype):
        """Add a data reference from the address `ea` to `target`.

        If the reftype `write` is true, then specify that this ref is writing to the target.
        """
        ea, target = interface.address.head(ea, target)
        isWrite = reftype.get('write', False)
        flowtype = idaapi.dr_W if isWrite else idaapi.dr_R
        idaapi.add_dref(ea, target, flowtype | idaapi.XREF_USER)
        return target in xref.data_down(ea)
    ad = utils.alias(add_data, 'xref')

    @utils.multicase()
    @staticmethod
    def rm_code():
        '''Delete _all_ the code references at the current address.'''
        return xref.rm_code(ui.current.address())
    @utils.multicase(ea=six.integer_types)
    @staticmethod
    def rm_code(ea):
        '''Delete _all_ the code references at `ea`.'''
        ea = interface.address.inside(ea)
        [ idaapi.del_cref(ea, target, 0) for target in xref.code_down(ea) ]
        return False if len(xref.code_down(ea)) > 0 else True
    @utils.multicase(ea=six.integer_types, target=six.integer_types)
    @staticmethod
    def rm_code(ea, target):
        '''Delete any code references at `ea` that point to address `target`.'''
        ea = interface.address.inside(ea)
        idaapi.del_cref(ea, target, 0)
        return target not in xref.code_down(ea)
    rc = utils.alias(rm_code, 'xref')

    @utils.multicase()
    @staticmethod
    def rm_data():
        '''Delete _all_ the data references at the current address.'''
        return xref.rm_data(ui.current.address())
    @utils.multicase(ea=six.integer_types)
    @staticmethod
    def rm_data(ea):
        '''Delete _all_ the data references at `ea`.'''
        ea = interface.address.inside(ea)
        [ idaapi.del_dref(ea, target) for target in xref.data_down(ea) ]
        return False if len(xref.data_down(ea)) > 0 else True
    @utils.multicase(ea=six.integer_types, target=six.integer_types)
    @staticmethod
    def rm_data(ea, target):
        '''Delete any data references at `ea` that point to address `target`.'''
        ea = interface.address.inside(ea)
        idaapi.del_dref(ea, target)
        return target not in xref.data_down(ea)
    rd = utils.alias(rm_data, 'xref')

    @utils.multicase()
    @staticmethod
    def erase():
        '''Clear all references at the current address.'''
        return xref.erase(ui.current.address())
    @utils.multicase(ea=six.integer_types)
    @staticmethod
    def erase(ea):
        '''Clear all references at the address `ea`.'''
        ea = interface.address.inside(ea)
        return all(ok for ok in [xref.rm_code(ea), xref.rm_data(ea)])
    rx = utils.alias(rm_data, 'xref')

x = xref    # XXX: ns alias

drefs, crefs = utils.alias(xref.data, 'xref'), utils.alias(xref.code, 'xref')
dxdown, dxup = utils.alias(xref.data_down, 'xref'), utils.alias(xref.data_up, 'xref')
cxdown, cxup = utils.alias(xref.code_down, 'xref'), utils.alias(xref.code_up, 'xref')
up, down = utils.alias(xref.up, 'xref'), utils.alias(xref.down, 'xref')

# create/erase a mark at the specified address in the .idb
class marks(object):
    """
    This namespace is for interacting with the marks table within the
    database. By default, this namespace is capable of yielding the
    `(address, description)` of each mark within the database.

    This allows one to manage the marks. Although it is suggested to
    utilize "tags" as they provide significantly more flexibility.
    Using marks allows for one to use IDA's mark window for quick
    navigation to a mark.

    The functions in this namespace can be used like::

        > for ea, descr in database.marks(): ...
        > database.marks.new('this is my description')
        > database.marks.remove(ea)
        > ea, descr = database.marks.by(ea)

    """
    MAX_SLOT_COUNT = 0x400
    table = {}

    # FIXME: implement a matcher class for this too
    def __new__(cls):
        '''Yields each of the marked positions within the database.'''
        listable = [item for item in cls.iterate()] # make a copy in-case someone is actively modifying it
        for ea, comment in listable:
            yield ea, comment
        return

    @utils.multicase(description=six.string_types)
    @classmethod
    @utils.string.decorate_arguments('description')
    def new(cls, description):
        '''Create a mark at the current address with the given `description`.'''
        return cls.new(ui.current.address(), description)
    @utils.multicase(ea=six.integer_types, description=six.string_types)
    @classmethod
    @utils.string.decorate_arguments('description')
    def new(cls, ea, description, **extra):
        '''Create a mark at the address `ea` with the given `description` and return its index.'''
        ea = interface.address.inside(ea)
        try:
            idx = cls.__find_slotaddress(ea)
            ea, res = cls.by_index(idx)
            logging.warning(u"{:s}.new({:#x}, {!r}{:s}) : Replacing mark {:d} at {:#x} and changing the description from \"{:s}\" to \"{:s}\".".format('.'.join([__name__, cls.__name__]), ea, description, u", {:s}".format(utils.string.kwargs(extra)) if extra else '', idx, ea, utils.string.escape(res, '"'), utils.string.escape(description, '"')))
        except (E.ItemNotFoundError, E.OutOfBoundsError):
            res, idx = None, cls.__free_slotindex()
            logging.info(u"{:s}.new({:#x}, {!r}{:s}) : Creating mark {:d} at {:#x} with the description \"{:s}\".".format('.'.join([__name__, cls.__name__]), ea, description, u", {:s}".format(utils.string.kwargs(extra)) if extra else '', idx, ea, utils.string.escape(description, '"')))
        cls.__set_description(idx, ea, description, **extra)
        return res

    @utils.multicase()
    @classmethod
    def remove(cls):
        '''Remove the mark at the current address.'''
        return cls.remove(ui.current.address())
    @utils.multicase(ea=six.integer_types)
    @classmethod
    def remove(cls, ea):
        '''Remove the mark at the specified address `ea` returning the previous description.'''
        ea = interface.address.inside(ea)
        idx = cls.__find_slotaddress(ea)
        descr = cls.__get_description(idx)
        cls.__set_description(idx, ea, '')
        logging.warning(u"{:s}.remove({:#x}) : Removed mark {:d} at {:#x} with the description \"{:s}\".".format('.'.join([__name__, cls.__name__]), ea, idx, ea, utils.string.escape(descr, '"')))
        return descr

    @classmethod
    def iterate(cls):
        '''Iterate through all of the marks in the database.'''
        count = 0
        try:
            for idx in builtins.range(cls.MAX_SLOT_COUNT):
                yield cls.by_index(idx)
        except (E.OutOfBoundsError, E.AddressNotFoundError):
            pass
        return

    @classmethod
    def length(cls):
        '''Return the number of marks in the database.'''
        listable = [item for item in cls.iterate()]
        return len(listable)

    @classmethod
    def by_index(cls, index):
        '''Return the `(address, description)` of the mark at the specified `index` in the mark list.'''
        if 0 <= index < cls.MAX_SLOT_COUNT:
            return (cls.__get_slotaddress(index), cls.__get_description(index))
        raise E.IndexOutOfBoundsError(u"{:s}.by_index({:d}) : The specified mark slot index ({:d}) is out of bounds ({:s}).".format('.'.join([__name__, cls.__name__]), index, index, ("{:d} < 0".format(index)) if index < 0 else ("{:d} >= MAX_SLOT_COUNT".format(index))))
    byindex = utils.alias(by_index, 'marks')

    @utils.multicase()
    @classmethod
    def by_address(cls):
        '''Return the mark at the current address.'''
        return cls.by_address(ui.current.address())
    @utils.multicase(ea=six.integer_types)
    @classmethod
    def by_address(cls, ea):
        '''Return the `(address, description)` of the mark at the given address `ea`.'''
        return cls.by_index(cls.__find_slotaddress(ea))
    by = byaddress = utils.alias(by_address, 'marks')

    ## Internal functions depending on which version of IDA is being used (<7.0)
    if idaapi.__version__ < 7.0:
        @classmethod
        def __location(cls, **attrs):
            '''Return a location_t object with the specified attributes.'''
            res = idaapi.curloc()
            [item for item in itertools.starmap(functools.partial(setattr, res), attrs.items())]
            return res

        @classmethod
        @utils.string.decorate_arguments('description')
        def __set_description(cls, index, ea, description, **extra):
            '''Modify the mark at `index` to point to the address `ea` with the specified `description`.'''
            res = cls.__location(ea=ea, x=extra.get('x', 0), y=extra.get('y', 0), lnnum=extra.get('y', 0))
            title, descr = map(utils.string.to, (description, description))
            res.mark(index, title, descr)
            #raise E.DisassemblerError(u"{:s}.set_description({:d}, {:#x}, {!r}{:s}) : Unable to get slot address for specified index.".format('.'.join([__name__, cls.__name__]), index, ea, description, u", {:s}".format(utils.string.kwargs(extra)) if extra else '')))
            return index

        @classmethod
        def __get_description(cls, index):
            '''Return the description of the mark at the specified `index`.'''
            res = cls.__location().markdesc(index)
            return utils.string.of(res)

        @classmethod
        def __find_slotaddress(cls, ea):
            '''Return the index of the mark at the specified address `ea`.'''
            # FIXME: figure out how to fail if this address isn't found
            res = itertools.islice(itertools.count(), cls.MAX_SLOT_COUNT)
            res, iterable = itertools.tee(map(cls.__get_slotaddress, res))
            try:
                count = len(builtins.list(itertools.takewhile(lambda item: item != ea, res)))
            except:
                raise E.AddressNotFoundError(u"{:s}.find_slotaddress({:#x}) : Unable to find specified slot address.".format('.'.join([__name__, cls.__name__]), ea))
            [item for item in itertools.islice(iterable, count)]
            if builtins.next(iterable) != ea:
                raise E.AddressNotFoundError(u"{:s}.find_slotaddress({:#x}) : Unable to find specified slot address.".format('.'.join([__name__, cls.__name__]), ea))
            return count

        @classmethod
        def __free_slotindex(cls):
            '''Return the index of the next available mark slot.'''
            return cls.length()

        @classmethod
        def __get_slotaddress(cls, index):
            '''Return the address of the mark at the specified `index`.'''
            loc = cls.__location()
            intp = idaapi.int_pointer()
            intp.assign(index)
            res = loc.markedpos(intp)
            if res == idaapi.BADADDR:
                raise E.AddressNotFoundError(u"{:s}.get_slotaddress({:d}) : Unable to get slot address for specified index.".format('.'.join([__name__, cls.__name__]), index))
            return address.head(res)

    ## Internal functions depending on which version of IDA is being used (>= 7.0)
    else:
        @classmethod
        @utils.string.decorate_arguments('description')
        def __set_description(cls, index, ea, description, **extra):
            '''Modify the mark at `index` to point to the address `ea` with the specified `description`.'''
            res = utils.string.to(description)
            idaapi.mark_position(ea, extra.get('lnnum', 0), extra.get('x', 0), extra.get('y', 0), index, res)
            #raise E.AddressNotFoundError(u"{:s}.set_description({:d}, {:#x}, {!r}{:s}) : Unable to get slot address for specified index.".format('.'.join([__name__, cls.__name__]), index, ea, description, u", {:s}".format(utils.string.kwargs(extra)) if extra else ''))
            return index

        @classmethod
        def __get_description(cls, index):
            '''Return the description of the mark at the specified `index`.'''
            res = idaapi.get_mark_comment(index)
            return utils.string.of(res)

        @classmethod
        def __find_slotaddress(cls, ea):
            '''Return the index of the mark at the specified address `ea`.'''
            res = itertools.islice(itertools.count(), cls.MAX_SLOT_COUNT)
            res, iterable = itertools.tee(map(cls.__get_slotaddress, res))
            try:
                count = len(builtins.list(itertools.takewhile(lambda item: item != ea, res)))
            except:
                raise E.AddressNotFoundError(u"{:s}.find_slotaddress({:#x}) : Unable to find specified slot address.".format('.'.join([__name__, cls.__name__]), ea))
            [item for item in itertools.islice(iterable, count)]
            if builtins.next(iterable) != ea:
                raise E.AddressNotFoundError(u"{:s}.find_slotaddress({:#x}) : Unable to find specified slot address.".format('.'.join([__name__, cls.__name__]), ea))
            return count

        @classmethod
        def __free_slotindex(cls):
            '''Return the index of the next available mark slot.'''
            res = builtins.next((i for i in builtins.range(cls.MAX_SLOT_COUNT) if idaapi.get_marked_pos(i) == idaapi.BADADDR), None)
            if res is None:
                raise OverflowError("{:s}.free_slotindex() : No free slots available for mark.".format('.'.join([__name__, 'marks', cls.__name__])))
            return res

        @classmethod
        def __get_slotaddress(cls, index):
            '''Get the address of the mark at index `index`.'''
            res = idaapi.get_marked_pos(index)
            if res == idaapi.BADADDR:
                raise E.AddressNotFoundError(u"{:s}.get_slotaddress({:d}) : Unable to get slot address for specified index.".format('.'.join([__name__, cls.__name__]), index))
            return address.head(res)

@utils.multicase()
def mark():
    '''Return the mark at the current address.'''
    _, res = marks.by_address(ui.current.address())
    return res
@utils.multicase(none=None.__class__)
def mark(none):
    '''Remove the mark at the current address.'''
    return mark(ui.current.address(), None)
@utils.multicase(ea=six.integer_types)
def mark(ea):
    '''Return the mark at the specified address `ea`.'''
    _, res = marks.by_address(ea)
    return res
@utils.multicase(description=six.string_types)
@utils.string.decorate_arguments('description')
def mark(description):
    '''Set the mark at the current address to the specified `description`.'''
    return mark(ui.current.address(), description)
@utils.multicase(ea=six.integer_types, none=None.__class__)
def mark(ea, none):
    '''Erase the mark at address `ea`.'''
    try:
        tag(ea, 'mark', None)
    except E.MissingTagError:
        pass
    color(ea, None)
    return marks.remove(ea)
@utils.multicase(ea=six.integer_types, description=six.string_types)
@utils.string.decorate_arguments('description')
def mark(ea, description):
    '''Sets the mark at address `ea` to the specified `description`.'''
    return marks.new(ea, description)

class extra(object):
    r"""
    This namespace is for interacting with IDA's "extra" comments that
    can be associated with an address. This allows one to prefix or
    suffix an address with a large block of text simulating a
    multilined or paragraph comment.

    To add extra comments, one can do this like::

        > res = database.ex.prefix(ea, 'this\nis\na\nmultilined\ncomment')
        > res = database.ex.suffix(ea, "whee\nok...i'm over it.")
        > database.ex.insert(ea, 1)
        > database.extra.append(ea, 2)

    """

    MAX_ITEM_LINES = 5000   # defined in cfg/ida.cfg according to python/idc.py
    MAX_ITEM_LINES = (idaapi.E_NEXT-idaapi.E_PREV) if idaapi.E_NEXT > idaapi.E_PREV else idaapi.E_PREV-idaapi.E_NEXT

    @classmethod
    def __has_extra__(cls, ea, base):
        sup, Fnetnode = internal.netnode.sup, getattr(idaapi, 'ea2node', utils.fidentity)
        return sup.get(Fnetnode(ea), base, type=memoryview) is not None

    @utils.multicase()
    @classmethod
    def has_prefix(cls):
        '''Return true if there are any extra comments that prefix the item at the current address.'''
        return cls.__has_extra__(ui.current.address(), idaapi.E_PREV)
    @utils.multicase()
    @classmethod
    def has_suffix(cls):
        '''Return true if there are any extra comments that suffix the item at the current address.'''
        return cls.__has_extra__(ui.current.address(), idaapi.E_NEXT)
    @utils.multicase(ea=six.integer_types)
    @classmethod
    def has_prefix(cls, ea):
        '''Return true if there are any extra comments that prefix the item at the address `ea`.'''
        return cls.__has_extra__(ea, idaapi.E_PREV)
    @utils.multicase(ea=six.integer_types)
    @classmethod
    def has_suffix(cls, ea):
        '''Return true if there are any extra comments that suffix the item at the address `ea`.'''
        return cls.__has_extra__(ea, idaapi.E_NEXT)
    prefixQ, suffixQ = utils.alias(has_prefix, 'extra'), utils.alias(has_suffix, 'extra')

    @classmethod
    def __count__(cls, ea, base):
        sup, Fnetnode = internal.netnode.sup, getattr(idaapi, 'ea2node', utils.fidentity)
        for i in builtins.range(cls.MAX_ITEM_LINES):
            row = sup.get(Fnetnode(ea), base + i, type=memoryview)
            if row is None: break
        return i or None

    if idaapi.__version__ < 7.0:
        @classmethod
        def __hide__(cls, ea):
            '''Hide the extra comments at the address `ea`.'''
            if type.flags(ea, idaapi.FF_LINE) == idaapi.FF_LINE:
                type.flags(ea, idaapi.FF_LINE, 0)
                return True
            return False

        @classmethod
        def __show__(cls, ea):
            '''Show the extra comments at the address `ea`.'''
            if type.flags(ea, idaapi.FF_LINE) != idaapi.FF_LINE:
                type.flags(ea, idaapi.FF_LINE, idaapi.FF_LINE)  # FIXME: IDA 7.0 : ida_nalt.set_visible_item?
                return True
            return False

        @classmethod
        def __get__(cls, ea, base):
            '''Fetch the extra comments from the address `ea` that are specified by the index in `base`.'''
            sup, Fnetnode = internal.netnode.sup, getattr(idaapi, 'ea2node', utils.fidentity)

            # count the number of rows
            count = cls.__count__(ea, base)
            if count is None: return None

            # now we can fetch them
            res = (sup.get(Fnetnode(ea), base + i, type=bytes) for i in builtins.range(count))

            # remove the null-terminator if there is one
            res = (row.rstrip(b'\0') for row in res)

            # fetch them from IDA and join them with newlines
            return '\n'.join(map(utils.string.of, res))
        @classmethod
        @utils.string.decorate_arguments('string')
        def __set__(cls, ea, string, base):
            '''Set the newline-delimited `string` as the extra comments for the address `ea` at the index specified by `base`.'''
            cls.__hide__(ea)
            sup, Fnetnode = internal.netnode.sup, getattr(idaapi, 'ea2node', utils.fidentity)

            # break the string up into rows, and encode each type for IDA
            res = [ utils.string.to(item) for item in string.split('\n') ]

            # assign them directly into IDA
            [ sup.set(Fnetnode(ea), base + i, row + b'\0') for i, row in enumerate(res) ]

            # now we can show (refresh) them
            cls.__show__(ea)

            # an exception before this happens would imply failure
            return True
        @classmethod
        def __delete__(cls, ea, base):
            '''Remove the extra comments from the address `ea` that start at the index in `base`.'''
            sup, Fnetnode = internal.netnode.sup, getattr(idaapi, 'ea2node', utils.fidentity)

            # count the number of rows to remove
            count = cls.__count__(ea, base)
            if count is None: return False

            # hide them before we modify it
            cls.__hide__(ea)

            # now we can remove them
            [ sup.remove(Fnetnode(ea), base + i) for i in builtins.range(count) ]

            # and then show (refresh) it
            cls.__show__(ea)
            return True
    else:
        @classmethod
        def __get__(cls, ea, base):
            '''Fetch the extra comments from the address `ea` that are specified by the index in `base`.'''
            # count the number of rows
            count = cls.__count__(ea, base)
            if count is None: return None

            # grab the extra comments from the database
            iterable = (idaapi.get_extra_cmt(ea, base + i) or '' for i in builtins.range(count))

            # convert them back into Python and join them with a newline
            iterable = (utils.string.of(item) for item in iterable)
            return '\n'.join(iterable)
        @classmethod
        @utils.string.decorate_arguments('string')
        def __set__(cls, ea, string, base):
            '''Set the newline-delimited `string` as the extra comments for the address `ea` at the index specified by `base`.'''
            # break the string up into rows, and encode each type for IDA
            iterable = (utils.string.to(item) for item in string.split('\n'))

            # assign them into IDA using its api
            [ idaapi.update_extra_cmt(ea, base + i, row) for i, row in enumerate(iterable) ]

            # return how many newlines there were
            return string.count('\n')
        @classmethod
        def __delete__(cls, ea, base):
            '''Remove the extra comments from the address `ea` that start at the index in `base`.'''

            # count the number of extra comments to remove
            res = cls.__count__(ea, base)
            if res is None: return 0

            # now we can delete them using the api
            [idaapi.del_extra_cmt(ea, base + i) for i in builtins.range(res)]

            # return how many comments we deleted
            return res

    @utils.multicase(ea=six.integer_types)
    @classmethod
    def __get_prefix__(cls, ea):
        '''Return the prefixed comment at address `ea`.'''
        return cls.__get__(ea, idaapi.E_PREV)

    @utils.multicase(ea=six.integer_types)
    @classmethod
    def __get_suffix__(cls, ea):
        '''Return the suffixed comment at address `ea`.'''
        return cls.__get__(ea, idaapi.E_NEXT)

    @utils.multicase(ea=six.integer_types)
    @classmethod
    def __delete_prefix__(cls, ea):
        '''Delete the prefixed comment at address `ea`.'''
        res = cls.__get__(ea, idaapi.E_PREV)
        cls.__delete__(ea, idaapi.E_PREV)
        return res
    @utils.multicase(ea=six.integer_types)
    @classmethod
    def __delete_suffix__(cls, ea):
        '''Delete the suffixed comment at address `ea`.'''
        res = cls.__get__(ea, idaapi.E_NEXT)
        cls.__delete__(ea, idaapi.E_NEXT)
        return res

    @utils.multicase(ea=six.integer_types, string=six.string_types)
    @classmethod
    def __set_prefix__(cls, ea, string):
        '''Set the prefixed comment at address `ea` to the specified `string`.'''
        res, ok = cls.__delete_prefix__(ea), cls.__set__(ea, string, idaapi.E_PREV)
        ok = cls.__set__(ea, string, idaapi.E_PREV)
        return res
    @utils.multicase(ea=six.integer_types, string=six.string_types)
    @classmethod
    def __set_suffix__(cls, ea, string):
        '''Set the suffixed comment at address `ea` to the specified `string`.'''
        res, ok = cls.__delete_suffix__(ea), cls.__set__(ea, string, idaapi.E_NEXT)
        return res

    @utils.multicase()
    @classmethod
    def __get_prefix__(cls):
        '''Return the prefixed comment at the current address.'''
        return cls.__get_prefix__(ui.current.address())
    @utils.multicase()
    @classmethod
    def __get_suffix__(cls):
        '''Return the suffixed comment at the current address.'''
        return cls.__get_suffix__(ui.current.address())
    @utils.multicase()
    @classmethod
    def __delete_prefix__(cls):
        '''Delete the prefixed comment at the current address.'''
        return cls.__delete_prefix__(ui.current.address())
    @utils.multicase()
    @classmethod
    def __delete_suffix__(cls):
        '''Delete the suffixed comment at the current address.'''
        return cls.__delete_suffix__(ui.current.address())
    @utils.multicase(string=six.string_types)
    @classmethod
    def __set_prefix__(cls, string):
        '''Set the prefixed comment at the current address to the specified `string`.'''
        return cls.__set_prefix__(ui.current.address(), string)
    @utils.multicase(string=six.string_types)
    @classmethod
    def __set_suffix__(cls, string):
        '''Set the suffixed comment at the current address to the specified `string`.'''
        return cls.__set_suffix__(ui.current.address(), string)

    @utils.multicase()
    @classmethod
    def prefix(cls):
        '''Return the prefixed comment at the current address.'''
        return cls.__get_prefix__(ui.current.address())
    @utils.multicase(string=six.string_types)
    @classmethod
    def prefix(cls, string):
        '''Set the prefixed comment at the current address to the specified `string`.'''
        return cls.__set_prefix__(ui.current.address(), string)
    @utils.multicase(none=None.__class__)
    @classmethod
    def prefix(cls, none):
        '''Delete the prefixed comment at the current address.'''
        return cls.__delete_prefix__(ui.current.address())
    @utils.multicase(ea=six.integer_types)
    @classmethod
    def prefix(cls, ea):
        '''Return the prefixed comment at address `ea`.'''
        return cls.__get_prefix__(ea)
    @utils.multicase(ea=six.integer_types, string=six.string_types)
    @classmethod
    def prefix(cls, ea, string):
        '''Set the prefixed comment at address `ea` to the specified `string`.'''
        return cls.__set_prefix__(ea, string)
    @utils.multicase(ea=six.integer_types, none=None.__class__)
    @classmethod
    def prefix(cls, ea, none):
        '''Delete the prefixed comment at address `ea`.'''
        return cls.__delete_prefix__(ea)

    @utils.multicase()
    @classmethod
    def suffix(cls):
        '''Return the suffixed comment at the current address.'''
        return cls.__get_suffix__(ui.current.address())
    @utils.multicase(string=six.string_types)
    @classmethod
    def suffix(cls, string):
        '''Set the suffixed comment at the current address to the specified `string`.'''
        return cls.__set_suffix__(ui.current.address(), string)
    @utils.multicase(none=None.__class__)
    @classmethod
    def suffix(cls, none):
        '''Delete the suffixed comment at the current address.'''
        return cls.__delete_suffix__(ui.current.address())
    @utils.multicase(ea=six.integer_types)
    @classmethod
    def suffix(cls, ea):
        '''Return the suffixed comment at address `ea`.'''
        return cls.__get_suffix__(ea)
    @utils.multicase(ea=six.integer_types, string=six.string_types)
    @classmethod
    def suffix(cls, ea, string):
        '''Set the suffixed comment at address `ea` to the specified `string`.'''
        return cls.__set_suffix__(ea, string)
    @utils.multicase(ea=six.integer_types, none=None.__class__)
    @classmethod
    def suffix(cls, ea, none):
        '''Delete the suffixed comment at address `ea`.'''
        return cls.__delete_suffix__(ea)

    @classmethod
    def __insert_space(cls, ea, count, getter_setter_remover):
        getter, setter, remover = getter_setter_remover

        res = getter(ea)
        lstripped, nl = ('', 0) if res is None else (res.lstrip('\n'), len(res) - len(res.lstrip('\n')) + 1)
        return setter(ea, '\n'*(nl + count - 1) + lstripped) if nl + count > 0 or lstripped else remover(ea)
    @classmethod
    def __append_space(cls, ea, count, getter_setter_remover):
        getter, setter, remover = getter_setter_remover

        res = getter(ea)
        rstripped, nl = ('', 0) if res is None else (res.rstrip('\n'), len(res) - len(res.rstrip('\n')) + 1)
        return setter(ea, rstripped + '\n'*(nl + count - 1)) if nl + count > 0 or rstripped else remover(ea)

    @utils.multicase(ea=six.integer_types, count=six.integer_types)
    @classmethod
    def preinsert(cls, ea, count):
        '''Insert `count` lines in front of the item at address `ea`.'''
        res = cls.__get_prefix__, cls.__set_prefix__, cls.__delete_prefix__
        return cls.__insert_space(ea, count, res)
    @utils.multicase(ea=six.integer_types, count=six.integer_types)
    @classmethod
    def preappend(cls, ea, count):
        '''Append `count` lines in front of the item at address `ea`.'''
        res = cls.__get_prefix__, cls.__set_prefix__, cls.__delete_prefix__
        return cls.__append_space(ea, count, res)

    @utils.multicase(ea=six.integer_types, count=six.integer_types)
    @classmethod
    def postinsert(cls, ea, count):
        '''Insert `count` lines after the item at address `ea`.'''
        res = cls.__get_suffix__, cls.__set_suffix__, cls.__delete_suffix__
        return cls.__insert_space(ea, count, res)
    @utils.multicase(ea=six.integer_types, count=six.integer_types)
    @classmethod
    def postappend(cls, ea, count):
        '''Append `count` lines after the item at address `ea`.'''
        res = cls.__get_suffix__, cls.__set_suffix__, cls.__delete_suffix__
        return cls.__append_space(ea, count, res)

    @utils.multicase(count=six.integer_types)
    @classmethod
    def preinsert(cls, count):
        '''Insert `count` lines in front of the item at the current address.'''
        return cls.preinsert(ui.current.address(), count)
    @utils.multicase(count=six.integer_types)
    @classmethod
    def preappend(cls, count):
        '''Append `count` lines in front of the item at the current address.'''
        return cls.preappend(ui.current.address(), count)

    @utils.multicase(count=six.integer_types)
    @classmethod
    def postinsert(cls, count):
        '''Insert `count` lines after the item at the current address.'''
        return cls.postinsert(ui.current.address(), count)
    @utils.multicase(count=six.integer_types)
    @classmethod
    def postappend(cls, count):
        '''Append `count` lines after the item at the current address.'''
        return cls.postappend(ui.current.address(), count)

    insert, append = utils.alias(preinsert, 'extra'), utils.alias(preappend, 'extra')
ex = extra  # XXX: ns alias

class set(object):
    """
    This namespace for setting the type of an address within the
    database. This allows one to apply a particular type to a given
    address. This allows one to specify whether a type is a string,
    undefined, code, data, an array, or even a structure.

    This can be used as in the following examples::

        > database.set.unknown(ea)
        > database.set.aligned(ea, alignment=0x10)
        > database.set.string(ea)
        > database.set.structure(ea, structure.by('mystructure'))

    """
    @utils.multicase(info=(six.string_types, idaapi.tinfo_t))
    def __new__(cls, info):
        '''Set the type information at the current address to `info`.'''
        return type(ui.current.address(), info)
    @utils.multicase(ea=six.integer_types, info=(six.string_types, idaapi.tinfo_t))
    def __new__(cls, ea, info):
        '''Set the type information at the address `ea` to `info`.'''
        # FIXME: instead of just setting the type, we need to use the type
        #        to actually modify the data at the specified address.
        return type(ea, info)
    info = typeinfo = utils.alias(__new__, 'set')

    @utils.multicase()
    @classmethod
    def unknown(cls):
        '''Set the data at the current address or selection to undefined.'''
        selection = ui.current.selection()
        if operator.eq(*(internal.interface.address.head(ea, silent=True) for ea in selection)):
            return cls.unknown(ui.current.address())
        start, stop = selection
        return cls.unknown(start, address.next(stop) - start)
    @utils.multicase(ea=six.integer_types)
    @classmethod
    def unknown(cls, ea):
        '''Set the data at address `ea` to undefined.'''
        size = idaapi.get_item_size(ea)
        if idaapi.__version__ < 7.0:
            ok = idaapi.do_unknown_range(ea, size, idaapi.DOUNK_SIMPLE)
        else:
            ok = idaapi.del_items(ea, idaapi.DELIT_SIMPLE, size)
        return size if ok and type.is_unknown(ea, size) else idaapi.get_item_size(ea) if type.is_unknown(ea) else 0
    @utils.multicase(ea=six.integer_types, size=six.integer_types)
    @classmethod
    def unknown(cls, ea, size):
        '''Set the data at address `ea` to undefined.'''
        if idaapi.__version__ < 7.0:
            ok = idaapi.do_unknown_range(ea, size, idaapi.DOUNK_SIMPLE)
        else:
            ok = idaapi.del_items(ea, idaapi.DELIT_SIMPLE, size)
        return size if ok and type.is_unknown(ea, size) else idaapi.get_item_size(ea) if type.is_unknown(ea) else 0
    undef = undefine = undefined = utils.alias(unknown, 'set')

    @utils.multicase()
    @classmethod
    def code(cls):
        '''Set the data at the current address to code.'''
        return cls.code(ui.current.address())
    @utils.multicase(ea=six.integer_types)
    @classmethod
    def code(cls, ea):
        '''Set the data at address `ea` to code.'''
        if idaapi.__version__ < 7.0:
            return idaapi.create_insn(ea)

        res = idaapi.insn_t()
        try:
            return idaapi.create_insn(ea, res)
        except TypeError:
            pass
        return idaapi.create_insn(res, ea)

    @utils.multicase(size=six.integer_types)
    @classmethod
    def data(cls, size, **type):
        '''Set the data at the current address to have the specified `size` and `type`.'''
        return cls.data(ui.current.address(), size, **type)
    @utils.multicase(ea=six.integer_types, size=six.integer_types)
    @classmethod
    def data(cls, ea, size, **type):
        """Set the data at address `ea` to have the specified `size` and `type`.

        If `type` is not specified, then choose the correct type based on the size.
        """

        ## Set some constants for anything older than IDA 7.0
        if idaapi.__version__ < 7.0:
            FF_STRUCT = idaapi.FF_STRU

            # Try and fetch some attributes..if we're unable to then we use None
            # as a placeholder so that we know that we need to use the older way
            # that IDA applies structures or alignment
            create_data, create_struct, create_align = idaapi.do_data_ex, getattr(idaapi, 'doStruct', None), getattr(idaapi, 'doAlign', None)

            lookup = {
                1 : idaapi.FF_BYTE, 2 : idaapi.FF_WORD, 4 : idaapi.FF_DWRD,
                8 : idaapi.FF_QWRD
            }

            # Older versions of IDA might not define FF_OWRD, so we just
            # try and add if its available. We fall back to an array anyways.
            if hasattr(idaapi, 'FF_OWRD'): lookup[16] = idaapi.FF_OWRD

        ## Set some constants used for IDA 7.0 and newer
        else:
            FF_STRUCT = idaapi.FF_STRUCT
            create_data, create_struct, create_align = idaapi.create_data, idaapi.create_struct, idaapi.create_align

            lookup = {
                1 : idaapi.FF_BYTE, 2 : idaapi.FF_WORD, 4 : idaapi.FF_DWORD,
                8 : idaapi.FF_QWORD, 16 : idaapi.FF_OWORD
            }

        ## Now we can apply the type to the given address
        try:
            res = type['type'] if 'type' in type else lookup[size]

        # If the size doesn't exist, then let the user know that we don't know what to do
        except KeyError:
            raise E.InvalidTypeOrValueError("{:s}.data({:#x}, {:d}{:s}) : Unable to determine the correct type for the specified size ({:+d}) to assign to the data.".format('.'.join([__name__, cls.__name__]), ea, size, u", {:s}".format(utils.string.kwargs(type)) if type else '', size))

        # Check if we need to use older IDA logic by checking of any of our api calls are None
        if idaapi.__version__ < 7.0 and any(f is None for f in [create_struct, create_align]):
            ok = create_data(ea, idaapi.FF_STRUCT if isinstance(res, _structure.structure_t) else res, size, res.id if isinstance(res, _structure.structure_t) else 0)

        # Otherwise we can create structures normally
        elif isinstance(res, (_structure.structure_t, idaapi.struc_t)):
            ok = create_struct(ea, size, res.id)

        # Or apply alignment properly...
        elif res == idaapi.FF_ALIGN and hasattr(idaapi, 'create_align'):
            ok = create_align(ea, size, 0)

        # Anything else is just regular data that we can fall back to
        else:
            ok = idaapi.create_data(ea, res, size, 0)

        # Return our new size if we were successful
        return idaapi.get_item_size(ea) if ok else 0

    @utils.multicase()
    @classmethod
    def alignment(cls, **alignment):
        '''Set the data at the current address as aligned with the specified `alignment`.'''
        return cls.align(ui.current.address(), **alignment)
    @utils.multicase(ea=six.integer_types)
    @classmethod
    def alignment(cls, ea, **alignment):
        """Set the data at address `ea` as aligned.

        If `alignment` is specified, then use it as the number of bytes to align the data to.
        If `size` is specified, then align that number of bytes.
        """
        if not type.is_unknown(ea):
            logging.warning("{:s}.set.alignment({:#x}{:s}) : Refusing to align the specified address ({:#x}) as it has already been defined.".format('.'.join([__name__, cls.__name__]), ea, u", {:s}".format(utils.string.kwargs(alignment)) if alignment else '', ea))  # XXX: define a custom warning
            return 0

        # alignment can only be determined if there's an actual size, so
        # we'll need some way to calculate the size if we weren't given one.
        def calculate_size(ea):

            # if the address is initialized, then we'll figure it out by
            # looking for bytes that repeat.
            if type.is_initialized(ea):
                size, by = 0, read(ea, 1)
                while read(ea + size, 1) == by:
                    size += 1
                return size

            # if it's uninitialized, then use the next label as the boundary
            # for calculating the size that we need.
            return address.nextlabel(ea) - ea

        # first of all, we need to check if idaapi.create_align exists,
        # because if it doesn't then we need to calculate things ourselves.
        if not hasattr(idaapi, 'create_align'):

            # grab the size out of the kwarg or calculate it if one wasn't given.
            size = alignment['size'] if operator.contains(alignment, 'size') else calculate_size(ea)

            # now we can just hand our size off to create_data because
            # this is the very best that we can do.
            return cls.data(ea, size, type=idaapi.FF_ALIGN)

        # otherwise we can actually use the create_align which can infer the
        # size and align it on our behalf. we'll start by trying to grab the
        # alignment and converting from a multiple to an actual exponent.
        align = builtins.next((alignment[k] for k in ['align', 'alignment'] if k in alignment), 0)
        e = math.trunc(math.floor(math.log(align, 2))) if align else 0

        # if we were given an alignment, then we'll need to convert it from
        # its multiple that the user wants to an actual exponent for the api.
        # next we'll need to grab the size if the user gave us one.
        if operator.contains(alignment, 'size'):
            size = alignment['size']

        # if our size is unset and we're using an older version of IDA, then
        # we actually need to figure the size out ourselves regardless.
        elif idaapi.__version__ < 7.6:
            size = alignment.get('size', calculate_size(ea))

        # if they didn't give us one, then we need at least one of them to
        # figure out the other. we do this by calculating the size ourselves.
        else:
            size = alignment.get('size', 0 if align else calculate_size(ea))

        # now we should be good to go and can return the new size or 0 on failure.
        if not idaapi.create_align(ea, size, e):
            return 0
        return idaapi.get_item_size(ea)
    align = aligned = utils.alias(alignment, 'set')

    @utils.multicase()
    @classmethod
    def string(cls, **strtype):
        '''Set the data at the current address to a string with the specified `strtype`.'''
        address, selection = ui.current.address(), ui.current.selection()
        if 'length' in strtype or operator.eq(*(internal.interface.address.head(ea, silent=True) for ea in selection)):
            return cls.string(address, **strtype)
        return cls.string(selection, **strtype)
    @utils.multicase(bounds=tuple)
    @classmethod
    def string(cls, bounds, **strtype):
        '''Set the data within the provided `bounds` to a string with the specified `strtype`.'''
        widthtype = {1: idaapi.STRWIDTH_1B, 2: idaapi.STRWIDTH_2B, 4: idaapi.STRWIDTH_4B}
        lengthtype = {0: idaapi.STRLYT_TERMCHR, 1: idaapi.STRLYT_PASCAL1, 2: idaapi.STRLYT_PASCAL2, 4: idaapi.STRLYT_PASCAL4}

        # Before we do anything, we're going to need to figure out what the string
        # type so that we can calculate what the actual string length will be.
        if any(item in strtype for item in ['strtype', 'type']):
            res = builtins.next(strtype[item] for item in ['strtype', 'type'] if item in strtype)
            width_t, length_t = res if isinstance(res, (builtins.list, builtins.tuple)) else (res, 0)

        # If we didn't get one, then we need to use the default one from the database.
        else:
            inf = config.info.strtype if idaapi.__version__ < 7.2 else idaapi.inf_get_strtype()
            width, layout = ((inf >> shift) & mask for shift, mask in [(0, idaapi.STRWIDTH_MASK), (idaapi.STRLYT_SHIFT, idaapi.STRLYT_MASK)])
            match_width = (item for item, value in widthtype.items() if value == width)
            match_layout = (item for item, value in lengthtype.items() if value == layout)
            width_t, length_t = builtins.next(match_width, 1), builtins.next(match_layout, 0)

        # Now we have the character width and the length prefix size. So to start out, we
        # take the difference between our bounds and subtract the layout length from it.
        distance = operator.sub(*reversed(sorted(bounds)))
        if length_t > distance:
            logging.warning("{:s}.string({!s}{:s}) : Attempting to apply a string with a prefix length ({:d}) that is larger than the given boundaries ({:s}).".format('.'.join([__name__, cls.__name__]), bounds, u", {!s}".format(utils.string.kwargs(strtype)) if strtype else '', length_t, bounds))
        leftover = distance - length_t if distance > length_t else 0

        # Next we can just take our total number of leftover bytes and divide it by the
        # character width to get the real string length that we'll use. We round it up
        # to ensure that the bounds the user gave us covers everything they selected.
        ea, _ = bounds
        return cls.string(ea, math.trunc(math.ceil(leftover / width_t)), **strtype)
    @utils.multicase(ea=six.integer_types)
    @classmethod
    def string(cls, ea, **strtype):
        '''Set the data at address `ea` to a string with the specified `strtype`.'''
        return cls.string(ea, strtype.pop('length', 0), **strtype)
    @utils.multicase(ea=six.integer_types, length=six.integer_types)
    @classmethod
    def string(cls, ea, length, **strtype):
        """Set the data at address `ea` to a string with the specified `length`.

        If the integer `strtype` is specified, then apply a string of the specified character width.
        If the tuple `strtype` is specified, the first item is the string's character width and the second item is the size of the length prefix.
        """
        widthtype = {1: idaapi.STRWIDTH_1B, 2: idaapi.STRWIDTH_2B, 4: idaapi.STRWIDTH_4B}
        lengthtype = {0: idaapi.STRLYT_TERMCHR, 1: idaapi.STRLYT_PASCAL1, 2: idaapi.STRLYT_PASCAL2, 4: idaapi.STRLYT_PASCAL4}

        # First try grab the type that the user gave us from the parameters. If it wasn't a tuple,
        # then convert it into one with a null-terminator, as the user might've just given us the
        # character width.
        if any(item in strtype for item in ['strtype', 'type']):
            res = builtins.next(strtype[item] for item in ['strtype', 'type'] if item in strtype)
            width_t, length_t = res if isinstance(res, (builtins.list, builtins.tuple)) else (res, 0)

        # Otherwise, we need to unpack the default one from the database into the width and layout.
        else:
            inf = config.info.strtype if idaapi.__version__ < 7.2 else idaapi.inf_get_strtype()
            width, layout = ((inf >> shift) & mask for shift, mask in [(0, idaapi.STRWIDTH_MASK), (idaapi.STRLYT_SHIFT, idaapi.STRLYT_MASK)])
            match_width = (item for item, value in widthtype.items() if value == width)
            match_layout = (item for item, value in lengthtype.items() if value == layout)
            width_t, length_t = builtins.next(match_width, 1), builtins.next(match_layout, 0)

        # Now we can just validate the width and the length size.
        if not operator.contains(widthtype, width_t):
            raise E.InvalidTypeOrValueError("{:s}.string({:#x}, {:d}{:s}) : The requested character width ({:d}) is unsupported.".format('.'.join([__name__, cls.__name__]), ea, length, u", {!s}".format(utils.string.kwargs(strtype)) if strtype else '', width_t))
        if not operator.contains(lengthtype, length_t):
            raise E.InvalidTypeOrValueError("{:s}.string({:#x}, {:d}{:s}) : An invalid size ({:d}) was provided for the string length prefix.".format('.'.join([__name__, cls.__name__]), ea, length, u", {!s}".format(utils.string.kwargs(strtype)) if strtype else '', length_t))

        # Convert the width and length into an actual size.
        size = width_t * length

        # Now we can combine them into the string type that IDA actually understands.
        res = (lengthtype[length_t] << idaapi.STRLYT_SHIFT) & idaapi.STRLYT_MASK
        res|= widthtype[width_t] & idaapi.STRWIDTH_MASK

        # If the size is larger than 0, then the user knows what they want and we
        # need to undefine that number of bytes first. The value of length_t is
        # added because we need to undefine the length prefix as well.
        if size > 0 and not type.is_unknown(ea):
            cb = cls.unknown(ea, length_t + size)
            if cb != length_t + size:
                raise E.DisassemblerError(u"{:s}.string({:#x}, {:d}{:s}) : Unable to undefine {:d} bytes for the requested string.".format('.'.join([__name__, cls.__name__]), ea, length, u", {:s}".format(utils.string.kwargs(strtype)) if strtype else '', length_t + size))

        # Make a string at the specified address of the suggested size with
        # the desired string type.
        ok = idaapi.make_ascii_string(ea, size and (size + length_t), res) if idaapi.__version__ < 7.0 else idaapi.create_strlit(ea, size and (size + length_t), res)
        if not ok:
            raise E.DisassemblerError(u"{:s}.string({:#x}, {:d}{:s}) : Unable to define the specified address as a string of the requested strtype {:#04x}.".format('.'.join([__name__, cls.__name__]), ea, length, u", {:s}".format(utils.string.kwargs(strtype)) if strtype else '', res))

        # In order to determine the correct length, we need to subtract the
        # length prefix the size, and divide the total by the character width.
        res = idaapi.get_item_size(ea) - length_t
        return get.string(ea, length=res // width_t)

    class integer(object):
        """
        This namespace used for applying various sized integer types to
        a particular address.

        This namespace is also aliased as ``database.set.i`` and can be used
        as follows::

            > database.set.i.uint8_t(ea)
            > database.set.i.uint64_t(ea)

        """
        @utils.multicase()
        def __new__(cls):
            '''Set the data at the current address to an integer.'''
            return cls(ui.current.address())
        @utils.multicase(ea=six.integer_types)
        def __new__(cls, ea):
            '''Set the data at address `ea` to an integer of a type determined by its size.'''
            res = type.size(ea)
            return cls(ea, res)
        @utils.multicase(ea=six.integer_types, size=six.integer_types)
        def __new__(cls, ea, size):
            '''Set the data at the address `ea` to an integer of the specified `size`.'''
            res = set.unknown(ea, size)
            if not type.is_unknown(ea, size) or res < size:
                raise E.DisassemblerError(u"{:s}({:#x}, {:d}) : Unable to undefine {:d} byte{:s} for the integer.".format('.'.join([__name__, 'set', cls.__name__]), ea, size, '' if size == 1 else 's'))

            ok = set.data(ea, size)
            if not ok:
                raise E.DisassemblerError(u"{:s}({:#x}, {:d}) : Unable to set the specified address to an integer ({:d}-bit).".format('.'.join([__name__, 'set', cls.__name__]), ea, size, 8 * size))
            return get.signed(ea, size) if type.flags(ea, idaapi.FF_SIGN) else get.unsigned(ea, size)

        @utils.multicase()
        @classmethod
        def uint8_t(cls):
            '''Set the data at the current address to a uint8_t.'''
            return cls.uint8_t(ui.current.address())
        @utils.multicase(ea=six.integer_types)
        @classmethod
        def uint8_t(cls, ea):
            '''Set the data at address `ea` to a uint8_t.'''
            res = set.unknown(ea, 1)
            if not type.is_unknown(ea, 1) or res < 1:
                raise E.DisassemblerError(u"{:s}.uint8_t({:#x}) : Unable to undefine {:d} byte for the integer.".format('.'.join([__name__, 'set', cls.__name__]), ea, 1))

            # Apply our data type after undefining it
            ok = set.data(ea, res, type=idaapi.FF_BYTE)
            if not ok:
                raise E.DisassemblerError(u"{:s}.uint8_t({:#x}) : Unable to set the specified address to an integer ({:d}-bit).".format('.'.join([__name__, 'set', cls.__name__]), ea, 8 * res))

            # Check if we need to flip the sign flag, and do it if necessary
            if type.flags(ea, idaapi.FF_SIGN):
                idaapi.toggle_sign(ea, 0)

            # Return our new size
            return get.unsigned(ea, res)
        @utils.multicase()
        @classmethod
        def sint8_t(cls):
            '''Set the data at the current address to a sint8_t.'''
            return cls.sint8_t(ui.current.address())
        @utils.multicase(ea=six.integer_types)
        @classmethod
        def sint8_t(cls, ea):
            '''Set the data at address `ea` to a sint8_t.'''
            res = set.unknown(ea, 1)
            if not type.is_unknown(ea, 1) or res < 1:
                raise E.DisassemblerError(u"{:s}.sint8_t({:#x}) : Unable to undefine {:d} byte for the integer.".format('.'.join([__name__, 'set', cls.__name__]), ea, 1))

            # Apply our data type after undefining it
            ok = set.data(ea, res, type=idaapi.FF_BYTE)
            if not ok:
                raise E.DisassemblerError(u"{:s}.sint8_t({:#x}) : Unable to set the specified address to an integer ({:d}-bit).".format('.'.join([__name__, 'set', cls.__name__]), ea, 8 * res))

            # Check if we need to flip the sign flag, and do it if necessary
            if not type.flags(ea, idaapi.FF_SIGN):
                idaapi.toggle_sign(ea, 0)

            # Return our new size
            return get.signed(ea, res)
        byte = utils.alias(uint8_t, 'set.integer')

        @utils.multicase()
        @classmethod
        def uint16_t(cls):
            '''Set the data at the current address to a uint16_t.'''
            return cls.uint16_t(ui.current.address())
        @utils.multicase(ea=six.integer_types)
        @classmethod
        def uint16_t(cls, ea):
            '''Set the data at address `ea` to a uint16_t.'''
            res = set.unknown(ea, 2)
            if not type.is_unknown(ea, 2) or res < 2:
                raise E.DisassemblerError(u"{:s}.uint16_t({:#x}) : Unable to undefine {:d} bytes for the integer.".format('.'.join([__name__, 'set', cls.__name__]), ea, 2))

            # Apply our data type after undefining it
            ok = set.data(ea, res, type=idaapi.FF_WORD)
            if not ok:
                raise E.DisassemblerError(u"{:s}.uint16_t({:#x}) : Unable to set the specified address to an integer ({:d}-bit).".format('.'.join([__name__, 'set', cls.__name__]), ea, 8 * res))

            # Check if we need to flip the sign flag, and do it if necessary
            if type.flags(ea, idaapi.FF_SIGN):
                idaapi.toggle_sign(ea, 0)

            # Return our new size
            return get.unsigned(ea, res)
        @utils.multicase()
        @classmethod
        def sint16_t(cls):
            '''Set the data at the current address to a sint16_t.'''
            return cls.sint16_t(ui.current.address())
        @utils.multicase(ea=six.integer_types)
        @classmethod
        def sint16_t(cls, ea):
            '''Set the data at address `ea` to a sint16_t.'''
            res = set.unknown(ea, 2)
            if not type.is_unknown(ea, 2) or res < 2:
                raise E.DisassemblerError(u"{:s}.sint16_t({:#x}) : Unable to undefine {:d} bytes for the integer.".format('.'.join([__name__, 'set', cls.__name__]), ea, 2))

            # Apply our data type after undefining it
            ok = set.data(ea, res, type=idaapi.FF_WORD)
            if not ok:
                raise E.DisassemblerError(u"{:s}.sint16_t({:#x}) : Unable to set the specfied address to an integer ({:d}-bit).".format('.'.join([__name__, 'set', cls.__name__]), ea, 8 * res))

            # Check if we need to flip the sign flag, and do it if necessary
            if not type.flags(ea, idaapi.FF_SIGN):
                idaapi.toggle_sign(ea, 0)

            # Return our new size
            return get.signed(ea, res)
        word = utils.alias(uint16_t, 'set.integer')

        @utils.multicase()
        @classmethod
        def uint32_t(cls):
            '''Set the data at the current address to a uint32_t.'''
            return cls.uint32_t(ui.current.address())
        @utils.multicase(ea=six.integer_types)
        @classmethod
        def uint32_t(cls, ea):
            '''Set the data at address `ea` to a uint32_t.'''
            FF_DWORD = idaapi.FF_DWORD if hasattr(idaapi, 'FF_DWORD') else idaapi.FF_DWRD

            # Undefine the data at the specified address
            res = set.unknown(ea, 4)
            if not type.is_unknown(ea, 4) or res < 4:
                raise E.DisassemblerError(u"{:s}.uint32_t({:#x}) : Unable to undefine {:d} bytes for the integer.".format('.'.join([__name__, 'set', cls.__name__]), ea, 4))

            # Apply our new data type after undefining it
            ok = set.data(ea, res, type=FF_DWORD)
            if not ok:
                raise E.DisassemblerError(u"{:s}.uint32_t({:#x}) : Unable to set the specified address to an integer ({:d}-bit).".format('.'.join([__name__, 'set', cls.__name__]), ea, 8 * res))

            # Check if we need to flip the sign flag, and do it if necessary
            if type.flags(ea, idaapi.FF_SIGN):
                idaapi.toggle_sign(ea, 0)

            # Now we can return our new size
            return get.unsigned(ea, res)
        @utils.multicase()
        @classmethod
        def sint32_t(cls):
            '''Set the data at the current address to a sint32_t.'''
            return cls.sint32_t(ui.current.address())
        @utils.multicase(ea=six.integer_types)
        @classmethod
        def sint32_t(cls, ea):
            '''Set the data at address `ea` to a sint32_t.'''
            FF_DWORD = idaapi.FF_DWORD if hasattr(idaapi, 'FF_DWORD') else idaapi.FF_DWRD

            # Undefine the data at the specified address
            res = set.unknown(ea, 4)
            if not type.is_unknown(ea, 4) or res < 4:
                raise E.DisassemblerError(u"{:s}.uint32_t({:#x}) : Unable to undefine {:d} bytes for the integer.".format('.'.join([__name__, 'set', cls.__name__]), ea, 4))

            # Apply our new data type after undefining it
            ok = set.data(ea, res, type=FF_DWORD)
            if not ok:
                raise E.DisassemblerError(u"{:s}.uint32_t({:#x}) : Unable to set the specified address to an integer ({:d}-bit).".format('.'.join([__name__, 'set', cls.__name__]), ea, 8 * res))

            # Check if we need to flip the sign flag, and do it if necessary
            if not type.flags(ea, idaapi.FF_SIGN):
                idaapi.toggle_sign(ea, 0)

            # Now we can return our new size
            return get.signed(ea, res)
        dword = utils.alias(uint32_t, 'set.integer')

        @utils.multicase()
        @classmethod
        def uint64_t(cls):
            '''Set the data at the current address to a uint64_t.'''
            return cls.uint64_t(ui.current.address())
        @utils.multicase(ea=six.integer_types)
        @classmethod
        def uint64_t(cls, ea):
            '''Set the data at address `ea` to a uint64_t.'''
            FF_QWORD = idaapi.FF_QWORD if hasattr(idaapi, 'FF_QWORD') else idaapi.FF_QWRD

            # Undefine the data at the specified address
            res = set.unknown(ea, 8)
            if not type.is_unknown(ea, 8) or res < 8:
                raise E.DisassemblerError(u"{:s}.uint64_t({:#x}) : Unable to undefine {:d} bytes for the integer.".format('.'.join([__name__, 'set', cls.__name__]), ea, 8))

            # Apply our new data type after undefining it
            ok = set.data(ea, res, type=FF_QWORD)
            if not ok:
                raise E.DisassemblerError(u"{:s}.uint64_t({:#x}) : Unable to set the specified address to an integer ({:d}-bit).".format('.'.join([__name__, 'set', cls.__name__]), ea, 8 * res))

            # Check if we need to flip the sign flag, and do it if necessary
            if type.flags(ea, idaapi.FF_SIGN):
                idaapi.toggle_sign(ea, 0)

            # Now we can return our new value since everything worked
            return get.unsigned(ea, res)
        @utils.multicase()
        @classmethod
        def sint64_t(cls):
            '''Set the data at the current address to a sint64_t.'''
            return cls.sint64_t(ui.current.address())
        @utils.multicase(ea=six.integer_types)
        @classmethod
        def sint64_t(cls, ea):
            '''Set the data at address `ea` to a sint64_t.'''
            FF_QWORD = idaapi.FF_QWORD if hasattr(idaapi, 'FF_QWORD') else idaapi.FF_QWRD

            # Undefine the data at the specified address
            res = set.unknown(ea, 8)
            if not type.is_unknown(ea, 8) or res < 8:
                raise E.DisassemblerError(u"{:s}.uint64_t({:#x}) : Unable to undefine {:d} bytes for the integer.".format('.'.join([__name__, 'set', cls.__name__]), ea, 8))

            # Apply our new data type after undefining it
            ok = set.data(ea, res, type=FF_QWORD)
            if not ok:
                raise E.DisassemblerError(u"{:s}.uint64_t({:#x}) : Unable to set the specified address to an integer ({:d}-bit).".format('.'.join([__name__, 'set', cls.__name__]), ea, 8 * res))

            # Check if we need to flip the sign flag, and do it if necessary
            if not type.flags(ea, idaapi.FF_SIGN):
                idaapi.toggle_sign(ea, 0)

            # Now we can return our new value since everything worked
            return get.signed(ea, res)
        qword = utils.alias(uint64_t, 'set.integer')

        @utils.multicase()
        @classmethod
        def uint128_t(cls):
            '''Set the data at the current address to an uint128_t.'''
            return cls.uint128_t(ui.current.address())
        @utils.multicase(ea=six.integer_types)
        @classmethod
        def uint128_t(cls, ea):
            '''Set the data at address `ea` to an uint128_t.'''
            FF_OWORD = idaapi.FF_OWORD if hasattr(idaapi, 'FF_OWORD') else idaapi.FF_OWRD

            # Undefine the data at the specified address
            res = set.unknown(ea, 16)
            if not type.is_unknown(ea, 16) or res < 16:
                raise E.DisassemblerError(u"{:s}.uint128_t({:#x}) : Unable to undefine {:d} bytes for the integer.".format('.'.join([__name__, 'set', cls.__name__]), ea, 16))

            # Apply our new data type after undefining it
            ok = set.data(ea, res, type=FF_OWORD)
            if not ok:
                raise E.DisassemblerError(u"{:s}.uint128_t({:#x}) : Unable to set the specified address to an integer ({:d}-bit).".format('.'.join([__name__, 'set', cls.__name__]), ea, 8 * res))

            # Check if we need to flip the sign flag, and do it if necessary
            if type.flags(ea, idaapi.FF_SIGN):
                idaapi.toggle_sign(ea, 0)

            # Now we can return our new value if we succeeded
            return get.signed(ea, res)
        @utils.multicase()
        @classmethod
        def sint128_t(cls):
            '''Set the data at the current address to a sint128_t.'''
            return cls.sint128_t(ui.current.address())
        @utils.multicase(ea=six.integer_types)
        @classmethod
        def sint128_t(cls, ea):
            '''Set the data at address `ea` to an sint128_t.'''
            FF_OWORD = idaapi.FF_OWORD if hasattr(idaapi, 'FF_OWORD') else idaapi.FF_OWRD

            # Undefine the data at the specified address
            res = set.unknown(ea, 16)
            if not type.is_unknown(ea, 16) or res < 16:
                raise E.DisassemblerError(u"{:s}.uint128_t({:#x}) : Unable to undefine {:d} bytes for the integer.".format('.'.join([__name__, 'set', cls.__name__]), ea, 16))

            # Apply our new data type after undefining it
            ok = set.data(ea, res, type=FF_OWORD)
            if not ok:
                raise E.DisassemblerError(u"{:s}.uint128_t({:#x}) : Unable to set the specified address to an integer ({:d}-bit).".format('.'.join([__name__, 'set', cls.__name__]), ea, 8 * res))

            # Check if we need to flip the sign flag, and do it if necessary
            if not type.flags(ea, idaapi.FF_SIGN):
                idaapi.toggle_sign(ea, 0)

            # Now we can return our new value if we succeeded
            return get.signed(ea, res)
        oword = utils.alias(uint128_t, 'set.integer')

    i = integer # XXX: ns alias

    class float(object):
        """
        This namespace used for applying various sized floating-point types
        to a particular address.

        This namespace is aliased as ``database.set.f`` and can be used as
        follows::

            > database.set.f.single(ea)
            > database.set.f.double(ea)

        """
        @utils.multicase()
        def __new__(cls):
            '''Sets the data at the current address to an IEEE-754 floating-point number based on its size.'''
            return cls(ui.current.address())
        @utils.multicase()
        def __new__(cls, ea):
            '''Sets the data at address `ea` to an IEEE-754 floating-point number based on its size.'''
            size = type.size(ea)
            if size < 4 and type.is_unknown(ea, 4):
                logging.warning(u"{:s}({:#x}) : Promoting number at address {:#x} to 32-bit single due to item size ({:+d}) being less than the smallest available IEEE-754 number ({:+d}).".format('.'.join([__name__, 'set', cls.__name__]), ea, size, 4))
                return cls.single(ea)
            elif size == 4:
                return cls.single(ea)
            elif size == 8:
                return cls.double(ea)
            raise E.InvalidTypeOrValueError(u"{:s}({:#x}) : Unable to determine the type of floating-point number for the item's size ({:+#x}).".format('.'.join([__name__, 'set', cls.__name__]), ea, size))

        @utils.multicase()
        @classmethod
        def single(cls):
            '''Set the data at the current address to an IEEE-754 single'''
            return cls.single(ui.current.address())
        @utils.multicase()
        @classmethod
        def single(cls, ea):
            '''Set the data at address `ea` to an IEEE-754 single.'''
            res = set.unknown(ea, 4)
            if not type.is_unknown(ea, 4) or res < 4:
                raise E.DisassemblerError(u"{:s}.single({:#x}) : Unable to undefine {:d} bytes for the float.".format('.'.join([__name__, 'set', cls.__name__]), ea, 4))

            # Apply our data type after undefining it
            ok = set.data(ea, res, type=idaapi.FF_FLOAT & 0xf0000000)
            if not ok:
                raise E.DisassemblerError(u"{:s}.single({:#x}) : Unable to assign a single to the specified address.".format('.'.join([__name__, 'set', cls.__name__]), ea))

            # Return our new value
            return get.float.single(ea)

        @utils.multicase()
        @classmethod
        def double(cls):
            '''Set the data at the current address to an IEEE-754 double'''
            return cls.double(ui.current.address())
        @utils.multicase()
        @classmethod
        def double(cls, ea):
            '''Set the data at address `ea` to an IEEE-754 double.'''
            res = set.unknown(ea, 8)
            if not type.is_unknown(ea, 8) or res < 8:
                raise E.DisassemblerError(u"{:s}.double({:#x}) : Unable to undefine {:d} bytes for the float.".format('.'.join([__name__, 'set', cls.__name__]), ea, 8))

            # Apply our data type after undefining it
            ok = set.data(ea, res, type=idaapi.FF_DOUBLE & 0xf0000000)
            if not ok:
                raise E.DisassemblerError(u"{:s}.double({:#x}) : Unable to assign a double to the specified address.".format('.'.join([__name__, 'set', cls.__name__]), ea))

            # Return our new value
            return get.float.double(ea)

    f = float   # XXX: ns alias

    @utils.multicase(type=_structure.structure_t)
    @classmethod
    def structure(cls, type):
        '''Set the data at the current address to the structure_t specified by `type`.'''
        return cls.structure(ui.current.address(), type)
    @utils.multicase(name=six.string_types)
    @classmethod
    def structure(cls, name):
        '''Set the data at the current address to the structure_t with the given `name`.'''
        return cls.structure(ui.current.address(), name)
    @utils.multicase(sptr=idaapi.struc_t)
    @classmethod
    def structure(cls, sptr):
        '''Set the data at the current address to the structure_t for the specified `sptr`.'''
        return cls.structure(ui.current.address(), sptr)
    @utils.multicase(ea=six.integer_types, type=_structure.structure_t)
    @classmethod
    def structure(cls, ea, type):
        '''Set the data at address `ea` to the structure_t specified by `type`.'''
        ok = cls.data(ea, type.size, type=type.ptr)
        if not ok:
            raise E.DisassemblerError(u"{:s}.structure({:#x}, {!r}) : Unable to define the specified address as a structure.".format('.'.join([__name__, cls.__name__]), ea, type))
        return get.structure(ea, type)
    @utils.multicase(ea=six.integer_types, name=six.string_types)
    @classmethod
    def structure(cls, ea, name):
        '''Set the data at address `ea` to the structure_t with the given `name`.'''
        st = _structure.by(name)
        return cls.structure(ea, st)
    @utils.multicase(ea=six.integer_types, sptr=idaapi.struc_t)
    @classmethod
    def structure(cls, ea, sptr):
        '''Set the data at address `ea` to the structure_t for the specified `sptr`.'''
        st = _structure.by(sptr)
        return cls.structure(ea, st)
    @utils.multicase(ea=six.integer_types, identifier=six.integer_types)
    @classmethod
    def structure(cls, ea, identifier):
        '''Set the data at address `ea` to the structure_t that has the specified `identifier`.'''
        st = _structure.by_identifier(identifier)
        return cls.structure(ea, st)

    struc = struct = utils.alias(structure, 'set')

    @utils.multicase()
    @classmethod
    def array(cls):
        '''Set the data at the current selection to an array of the type at the current address.'''
        ea, item = ui.current.address(), type.array()

        # Extract the type from the current address and use it to get its size.
        original_type, original_length = item
        _, _, nbytes = interface.typemap.resolve(original_type)

        # If the length at the current address is irrelevant, then we can just
        # chain to the other selection code using the type that we snagged.
        if original_length <= 1:
            return cls.array(original_type)

        # Otherwise we grab the selection and unpack it in order to calculate
        # the new length and determine if we need to warn the user about it.
        start, stop = ui.current.selection()
        result = math.ceil((stop - start) / nbytes)

        # Now we compare if the user is asking us to change the length in some way.
        length = math.trunc(result)
        if original_length > 1 and length != original_length:
            logging.warning(u"{:s}.array() : Modifying the number of elements ({:d}) for the array at the current selection ({:#x}<>{:#x}) to {:d}.".format('.'.join([__name__, cls.__name__]), original_length, start, stop, length))
        return cls.array(original_type, length)
    @utils.multicase(length=six.integer_types)
    @classmethod
    def array(cls, length):
        '''Set the data at the current selection to an array of the specified `length` using the type at the current address.'''
        ea, item = ui.current.address(), type.array()
        original_type, original_length = item

        # If the length is being changed, then warn the user about it.
        if original_length > 1 and original_length != length:
            logging.warning(u"{:s}.array({:d}) : Modifying the number of elements ({:d}) for the array at the current address ({:#x}) to {:d}.".format('.'.join([__name__, cls.__name__]), length, original_length, ea, length))
        return cls.array(ea, original_type, length)
    @utils.multicase()
    @classmethod
    def array(cls, type, **length):
        '''Set the data at the current address to an array of the specified `type` using the length determined from the current selection if `length` is not specified.'''
        if 'length' in length and isinstance(type, list):
            ttype, tlength = type
            if tlength != length['length']:
                raise E.InvalidParameterError(u"{:s}.array({!r}{:s}) : Multiple values for the array length were passed in the type ({:d}) and the parameter ({:d}).".format('.'.join([__name__, cls.__name__]), ttype, ", {:s}".format(utils.string.kwargs(length)) if length else '', tlength, length['length']))
            return cls.array(ui.current.address(), ttype, tlength)
        elif isinstance(type, list):
            type, length = type
            return cls.array(ui.current.address(), type, length)
        elif 'length' in length:
            return cls.array(ui.current.address(), type, length['length'])

        # If no length was specified, then we'll check the current selection.
        selection = ui.current.selection()
        if operator.eq(*(internal.interface.address.head(ea, silent=True) for ea in selection)):
            return cls.array(ui.current.address(), type)
        start, stop = selection
        return cls.array((start, address.next(stop)), type)
    @utils.multicase(ea=six.integer_types)
    @classmethod
    def array(cls, ea, type):
        '''Set the data at the address `ea` to an array of the given `type`.'''
        type, length = type if isinstance(type, builtins.list) else (type, 1)
        return cls.array(ea, type, length)
    @utils.multicase(bounds=tuple)
    @classmethod
    def array(cls, bounds, type):
        '''Set the data at the provided `bounds` to an array of the given `type`.'''
        if isinstance(type, builtins.list):
            raise E.InvalidParameterError(u"{:s}.array({!s}, {!r}) : Unable to set the provided boundary ({!r}) to the specified type ({!s}) due to it resulting in another array.".format('.'.join([__name__, cls.__name__]), bounds, type, bounds, type))
        start, stop = sorted(bounds)

        # Calculate the size of the type that we were given.
        _, _, nbytes = interface.typemap.resolve(type)
        length = operator.sub(*reversed(sorted(bounds)))

        # Now we can use it to calculate the length and apply it.
        res = math.ceil(length / nbytes)
        return cls.array(start, type, math.trunc(res))
    @utils.multicase(ea=six.integer_types, length=six.integer_types)
    @classmethod
    def array(cls, ea, type, length):
        '''Set the data at the address `ea` to an array with the given `length` and `type`.'''

        # if the type is already specifying a list, then combine it with
        # the specified length
        if isinstance(type, list):
            t, l = type
            realtype, reallength = [t, l * length], l * length

        # otherwise, promote it into an array
        else:
            realtype, reallength = [type, length], length

        # now we can figure out its IDA type and create the data. after
        # that, though, we need to update its refinfo before we leave.
        flags, typeid, nbytes = interface.typemap.resolve(realtype)
        if not idaapi.create_data(ea, flags, nbytes, typeid):
            raise E.DisassemblerError(u"{:s}.array({:#x}, {!r}, {:d}) : Unable to define the specified address as an array.".format('.'.join([__name__, cls.__name__]), ea, type, length))
        interface.address.update_refinfo(ea, flags)

        # return the array that we just created.
        return get.array(ea, length=reallength)

class get(object):
    """
    This namespace used to fetch and decode the data from the database
    at a given address. This allows one to interpret the semantics of
    parts of the database and then perform an action based on what was
    decoded. This includes standard functions for reading integers of
    different sizes, decoding structures, and even reading of arrays
    from the database.

    In order to decode various things out of the database, some of the
    following examples can be used::

        > res = database.get.signed()
        > res = database.get.unsigned(ea, 8, byteorder='big')
        > res = database.get.array(ea)
        > res = database.get.array(length=42)
        > res = database.get.structure(ea)
        > res = database.get.structure(ea, structure=structure.by('mystructure'))

    """
    @utils.multicase()
    @classmethod
    def info(cls):
        '''Return the type information for the current address as an ``idaapi.tinfo_t``.'''
        return cls.info(ui.current.address())
    @utils.multicase(ea=six.integer_types)
    @classmethod
    def info(cls, ea):
        '''Return the type information for the address `ea` as an ``idaapi.tinfo_t``.'''
        return type(ea)
    typeinfo = utils.alias(info, 'get')

    @utils.multicase()
    @classmethod
    def unsigned(cls, **byteorder):
        '''Read an unsigned integer from the current address.'''
        ea = ui.current.address()
        return cls.unsigned(ea, type.size(ea), **byteorder)
    @utils.multicase(ea=six.integer_types)
    @classmethod
    def unsigned(cls, ea, **byteorder):
        '''Read an unsigned integer from the address `ea` using the size defined in the database.'''
        return cls.unsigned(ea, type.size(ea), **byteorder)
    @utils.multicase(ea=six.integer_types, size=six.integer_types)
    @classmethod
    def unsigned(cls, ea, size, **byteorder):
        """Read an unsigned integer from the address `ea` with the specified `size`.

        If `byteorder` is 'big' then read in big-endian form.
        If `byteorder` is 'little' then read in little-endian form.

        The default value of `byteorder` is the same as specified by the database architecture.
        """
        data = read(ea, size)
        endian = byteorder.get('order', None) or byteorder.get('byteorder', config.byteorder())
        if endian.lower().startswith('little'):
            data = data[::-1]
        return functools.reduce(lambda agg, byte: agg << 8 | byte, bytearray(data), 0)

    @utils.multicase()
    @classmethod
    def signed(cls, **byteorder):
        '''Read a signed integer from the current address.'''
        ea = ui.current.address()
        return cls.signed(ea, type.size(ea), **byteorder)
    @utils.multicase(ea=six.integer_types)
    @classmethod
    def signed(cls, ea, **byteorder):
        '''Read a signed integer from the address `ea` using the size defined in the database.'''
        return cls.signed(ea, type.size(ea), **byteorder)
    @utils.multicase(ea=six.integer_types, size=six.integer_types)
    @classmethod
    def signed(cls, ea, size, **byteorder):
        """Read a signed integer from the address `ea` with the specified `size`.

        If `byteorder` is 'big' then read in big-endian form.
        If `byteorder` is 'little' then read in little-endian form.

        The default value of `byteorder` is the same as specified by the database architecture.
        """
        bits = 8 * size
        sf = pow(2, bits) >> 1
        res = cls.unsigned(ea, size, **byteorder)
        return (res - pow(2, bits)) if res & sf else res

    class integer(object):
        """
        This namespace contains the different ISO standard integer types that
        can be used to read integers out of the database.

        This namespace is also aliased as ``database.get.i`` and can be used
        like in the following examples::

            > res = database.get.i.uint32_t()
            > res = database.get.i.sint64_t(ea)
            > res = database.get.i.uint8_t(ea)

        """
        @utils.multicase()
        def __new__(cls, **byteorder):
            '''Read an integer from the current address.'''
            return get.signed(**byteorder) if type.flags(ui.current.address(), idaapi.FF_SIGN) else get.unsigned(**byteorder)
        @utils.multicase(ea=six.integer_types)
        def __new__(cls, ea, **byteorder):
            '''Read an integer from the address `ea`.'''
            return get.signed(ea, **byteorder) if type.flags(ea, idaapi.FF_SIGN) else get.unsigned(ea, **byteorder)
        @utils.multicase(ea=six.integer_types, size=six.integer_types)
        def __new__(cls, ea, size, **byteorder):
            '''Read an integer of the specified `size` from the address `ea`.'''
            return get.signed(ea, size, **byteorder) if type.flags(ea, idaapi.FF_SIGN) else get.unsigned(ea, size, **byteorder)

        @utils.multicase()
        @classmethod
        def uint8_t(cls, **byteorder):
            '''Read a uint8_t from the current address.'''
            return get.unsigned(ui.current.address(), 1, **byteorder)
        @utils.multicase(ea=six.integer_types)
        @classmethod
        def uint8_t(cls, ea, **byteorder):
            '''Read a uint8_t from the address `ea`.'''
            return get.unsigned(ea, 1, **byteorder)
        @utils.multicase()
        @classmethod
        def sint8_t(cls, **byteorder):
            '''Read a sint8_t from the current address.'''
            return get.signed(ui.current.address(), 1, **byteorder)
        @utils.multicase(ea=six.integer_types)
        @classmethod
        def sint8_t(cls, ea, **byteorder):
            '''Read a sint8_t from the address `ea`.'''
            return get.signed(ea, 1, **byteorder)
        byte = utils.alias(uint8_t, 'get.integer')

        @utils.multicase()
        @classmethod
        def uint16_t(cls, **byteorder):
            '''Read a uint16_t from the current address.'''
            return get.unsigned(ui.current.address(), 2, **byteorder)
        @utils.multicase(ea=six.integer_types)
        @classmethod
        def uint16_t(cls, ea, **byteorder):
            '''Read a uint16_t from the address `ea`.'''
            return get.unsigned(ea, 2, **byteorder)
        @utils.multicase()
        @classmethod
        def sint16_t(cls, **byteorder):
            '''Read a sint16_t from the current address.'''
            return get.signed(ui.current.address(), 2, **byteorder)
        @utils.multicase(ea=six.integer_types)
        @classmethod
        def sint16_t(cls, ea, **byteorder):
            '''Read a sint16_t from the address `ea`.'''
            return get.signed(ea, 2, **byteorder)
        word = utils.alias(uint16_t, 'get.integer')

        @utils.multicase()
        @classmethod
        def uint32_t(cls, **byteorder):
            '''Read a uint32_t from the current address.'''
            return get.unsigned(ui.current.address(), 4, **byteorder)
        @utils.multicase(ea=six.integer_types)
        @classmethod
        def uint32_t(cls, ea, **byteorder):
            '''Read a uint32_t from the address `ea`.'''
            return get.unsigned(ea, 4, **byteorder)
        @utils.multicase()
        @classmethod
        def sint32_t(cls, **byteorder):
            '''Read a sint32_t from the current address.'''
            return get.signed(ui.current.address(), 4, **byteorder)
        @utils.multicase(ea=six.integer_types)
        @classmethod
        def sint32_t(cls, ea, **byteorder):
            '''Read a sint32_t from the address `ea`.'''
            return get.signed(ea, 4, **byteorder)
        dword = utils.alias(uint32_t, 'get.integer')

        @utils.multicase()
        @classmethod
        def uint64_t(cls, **byteorder):
            '''Read a uint64_t from the current address.'''
            return get.unsigned(ui.current.address(), 8, **byteorder)
        @utils.multicase(ea=six.integer_types)
        @classmethod
        def uint64_t(cls, ea, **byteorder):
            '''Read a uint64_t from the address `ea`.'''
            return get.unsigned(ea, 8, **byteorder)
        @utils.multicase()
        @classmethod
        def sint64_t(cls, **byteorder):
            '''Read a sint64_t from the current address.'''
            return get.signed(ui.current.address(), 8, **byteorder)
        @utils.multicase(ea=six.integer_types)
        @classmethod
        def sint64_t(cls, ea, **byteorder):
            '''Read a sint64_t from the address `ea`.'''
            return get.signed(ea, 8, **byteorder)
        qword = utils.alias(uint64_t, 'get.integer')

        @utils.multicase()
        @classmethod
        def uint128_t(cls, **byteorder):
            '''Read a uint128_t from the current address.'''
            return get.unsigned(ui.current.address(), 16)
        @utils.multicase(ea=six.integer_types)
        @classmethod
        def uint128_t(cls, ea, **byteorder):
            '''Read a uint128_t from the address `ea`.'''
            return get.unsigned(ea, 16, **byteorder)
        @utils.multicase()
        @classmethod
        def sint128_t(cls, **byteorder):
            '''Read a sint128_t from the current address.'''
            return get.signed(ui.current.address(), 16)
        @utils.multicase(ea=six.integer_types)
        @classmethod
        def sint128_t(cls, ea, **byteorder):
            '''Read a sint128_t from the address `ea`.'''
            return get.signed(ea, 16, **byteorder)
        oword = utils.alias(uint128_t, 'get.integer')

    i = integer # XXX: ns alias

    class float(object):
        """
        This namespace contains a number of functions for fetching floating
        point numbers out of the database. These floating-point numbers are
        encoded according to the IEEE-754 specification.

        This namespace is also aliased as ``database.get.f`` and can be used
        as in the following examples::

            > res = database.get.f.half()
            > res = database.get.f.single(ea)
            > res = database.get.f.double(ea)

        If one needs to describe a non-standard encoding for a floating-point
        number, one can use the ``database.float`` function. This function
        takes a tuple representing the number of bits for the different
        components of a floating-point number. This can be used as in the
        following for reading a floating-point "half" from the database::

            > res = database.get.float(components=(10, 5, 1))

        This specifies 10-bits for the mantissa, 5 for the exponent, and 1
        bit for the signed flag. This allows one to specify arbitrary
        encodings for different floating-point numbers.
        """

        @utils.multicase()
        def __new__(cls, **byteorder):
            '''Read a floating-number from the current address using the number type that matches its size.'''
            return cls(ui.current.address(), **byteorder)
        @utils.multicase(ea=six.integer_types)
        def __new__(cls, ea, **byteorder):
            '''Read a floating-number at the address `ea` using the number type that matches its size.'''
            size = type.size(ea)
            if size == 2:
                return cls.half(ea, **byteorder)
            elif size == 4:
                return cls.single(ea, **byteorder)
            elif size == 8:
                return cls.double(ea, **byteorder)
            elif size > 8:
                logging.warning(u"{:s}({:#x}) : Demoting size ({:+d}) for floating-point number at {:#x} down to largest available IEEE-754 number ({:+d}).".format('.'.join([__name__, 'get', cls.__name__]), ea, size, ea, 8))
                return cls.double(ea, **byteorder)
            raise E.InvalidTypeOrValueError(u"{:s}({:#x}) : Unable to determine the type of floating-point number for the item's size ({:+#x}).".format('.'.join([__name__, 'get', cls.__name__]), ea, size))

        @utils.multicase(components=tuple)
        def __new__(cls, components, **byteorder):
            '''Read a floating-point number at the current address encoded with the specified `components`.'''
            return cls(ui.current.address(), components, **byteorder)
        @utils.multicase(ea=six.integer_types, components=tuple)
        def __new__(cls, ea, components, **byteorder):
            """Read a floating-point number at the address `ea` that is encoded with the specified `components`.

            The `components` parameter is a tuple (mantissa, exponent, sign) representing the number of bits for each component of the floating-point number.
            If `byteorder` is 'big' then read in big-endian form.
            If `byteorder` is 'little' then read in little-endian form.

            The default value of `byteorder` is the same as specified by the database architecture.
            """
            cb = sum(components) // 8

            # Read our data from the database as an integer, as we'll use this
            # to decode our individual components.
            integer = get.unsigned(ea, cb, **byteorder)

            # Unpack the components the user gave us.
            fraction, exponent, sign = components

            # Use the components to decode the floating point number
            try:
                res = utils.float_of_integer(integer, fraction, exponent, sign)

            except ValueError as message:
                raise ValueError(u"{:s}({:#x}, {!s}) : {!s}".format('.'.join([__name__, cls.__name__]), ea, components, message))

            return res

        @utils.multicase()
        @classmethod
        def half(cls, **byteorder):
            '''Read a half from the current address.'''
            return cls.half(ui.current.address(), **byteorder)
        @utils.multicase()
        @classmethod
        def half(cls, ea, **byteorder):
            '''Read a half from the address `ea`.'''
            bits = 10, 5, 1
            return cls(ea, bits, **byteorder)

        @utils.multicase()
        @classmethod
        def single(cls, **byteorder):
            '''Read a single from the current address.'''
            return cls.single(ui.current.address(), **byteorder)
        @utils.multicase()
        @classmethod
        def single(cls, ea, **byteorder):
            '''Read a single from the address `ea`.'''
            bits = 23, 8, 1
            return cls(ea, bits, **byteorder)

        @utils.multicase()
        @classmethod
        def double(cls, **byteorder):
            '''Read a double from the current address.'''
            return cls.double(ui.current.address(), **byteorder)
        @utils.multicase()
        @classmethod
        def double(cls, ea, **byteorder):
            '''Read a double from the address `ea`.'''
            bits = 52, 11, 1
            return cls(ea, bits, **byteorder)

    f = float   # XXX: ns alias

    @utils.multicase()
    @classmethod
    def array(cls, **length):
        '''Return the values of the array at the current address.'''
        address, selection = ui.current.address(), ui.current.selection()
        if 'length' in length or operator.eq(*(internal.interface.address.head(ea, silent=True) for ea in selection)):
            return cls.array(address, **length)
        return cls.array(selection)
    @utils.multicase(bounds=tuple)
    @classmethod
    def array(cls, bounds):
        '''Return the values within the provided `bounds` as an array.'''
        start, stop = sorted(bounds)
        length = (stop - start) / idaapi.get_item_size(start)
        return cls.array(start, length=math.trunc(math.ceil(length)))
    @utils.multicase(bounds=tuple)
    @classmethod
    def array(cls, bounds, type):
        '''Return the values within the provided `bounds` as an array of the pythonic element `type`.'''
        start, stop = sorted(bounds)

        # figure out the element size from our pythonic type parameter.
        _, _, size = interface.typemap.resolve(type)

        # the bounds might not divide evenly by the given type, but we want
        # to lean towards reading too much rather than reading too little.
        length = (stop - start) / size
        count = math.trunc(math.ceil(length))
        return cls.array(start, length=count, type=type)
    @utils.multicase(ea=six.integer_types)
    @classmethod
    def array(cls, ea, **length):
        """Return the values of the array at the address specified by `ea`.

        If the integer `length` is defined, then use it as the number of elements for the array.
        If a pythonic type is passed to `type`, then use it for the element type of the array when decoding.
        """
        ea = interface.address.within(ea) if 'length' not in length else ea

        # FIXME: this function is just too fucking large...srsly.
        FF_STRUCT = idaapi.FF_STRUCT if hasattr(idaapi, 'FF_STRUCT') else idaapi.FF_STRU
        FF_STRLIT = idaapi.FF_STRLIT if hasattr(idaapi, 'FF_STRLIT') else idaapi.FF_ASCI

        def numeric_lookup_tables():
            '''
            This closure is responsible for returning the lookup tables to map IDA types to
            either lengths or array typecodes which will be used for decoding the elements
            of the array.
            '''

            # This numerics table is responsible for mapping an idaapi.DT_TYPE
            # type to a typecode for the _array class.
            numerics = {
                idaapi.FF_BYTE : utils.get_array_typecode(1),
                idaapi.FF_WORD : utils.get_array_typecode(2),
                idaapi.FF_DWORD if hasattr(idaapi, 'FF_DWORD') else idaapi.FF_DWRD : utils.get_array_typecode(4),
                idaapi.FF_FLOAT : 'f',
                idaapi.FF_DOUBLE : 'd',
            }

            # Some 32-bit versions of python might not have array.array('Q')
            # and some versions of IDA also might not have FF_QWORD..
            try:
                _array.array(utils.get_array_typecode(8))
                numerics[idaapi.FF_QWORD if hasattr(idaapi, 'FF_QWORD') else idaapi.FF_QWRD] = utils.get_array_typecode(8)
            except (AttributeError, ValueError):
                pass

            # This long-numerics table is a mapping-type for converting an
            # idaapi.DT_TYPE to a length. This way we can manually read the
            # elements of the array into a list that we can return to the user.
            lnumerics = {
                idaapi.FF_BYTE : 1, idaapi.FF_ALIGN : 1,
                idaapi.FF_WORD : 2,
                idaapi.FF_DWORD if hasattr(idaapi, 'FF_DWORD') else idaapi.FF_DWRD : 4,
                idaapi.FF_FLOAT : 4,
                idaapi.FF_DOUBLE : 8,
            }

            # If we have FF_QWORD defined but it cannot be represented by the
            # _array class, then we'll need to add its size to our long-numerics
            # table so that we can still read its elements manually.
            if any(hasattr(idaapi, name) for name in {'FF_QWRD', 'FF_QWORD'}):
                name = builtins.next(name for name in {'FF_QWRD', 'FF_QWORD'} if hasattr(idaapi, name))
                value = getattr(idaapi, name)
                if value not in numerics:
                    lnumerics[value] = 8
                pass

            # FF_OWORD, FF_YWORD and FF_ZWORD might not exist in older versions
            # of IDA, so try to add them to our long-numerics "softly".
            try:
                lnumerics[idaapi.FF_QWORD if hasattr(idaapi, 'FF_QWORD') else idaapi.FF_QWRD] = 8
                lnumerics[idaapi.FF_OWORD if hasattr(idaapi, 'FF_OWORD') else idaapi.FF_OWRD] = 16
                lnumerics[idaapi.FF_YWORD if hasattr(idaapi, 'FF_YWORD') else idaapi.FF_YWRD] = 32
                lnumerics[idaapi.FF_ZWORD if hasattr(idaapi, 'FF_ZWORD') else idaapi.FF_ZWRD] = 64
            except AttributeError:
                pass

            # Depending on the version of IDAPython, some of IDA's flags (FF_*) can
            # be signed or unsigned. Since we're explicitly testing for them by using
            # container membership, we'll need to ensure that they're unsigned when
            # storing them into their lookup tables. This way our membership tests
            # will actually work when determining the types to use.
            numerics = { idaapi.as_uint32(ff) : typecode for ff, typecode in numerics.items() }
            lnumerics = { idaapi.as_uint32(ff) : length for ff, length in lnumerics.items() }

            # Now they're safe to return to the caller for people to use.
            return numerics, lnumerics

        def decode_array(ea, T, count, numerics, lnumerics):
            '''
            This closure is responsible for decoding an array from the given address
            using the provided type (T) and count for the number of elements. The
            `numerics` and `lnumerics` tables are used for looking up the typecode
            or length given a DT_TYPE.
            '''

            # If the array has a refinfo_t at its address or the signed flag is
            # set, then we need to lowercase the typecode to get signed or
            # relative values from the array.
            if interface.address.refinfo(ea) or F & idaapi.FF_SIGN:

                # FIXME: If the user has set the signed flag, then we need to return
                #        the negative values that are displayed instead of just
                #        decoding the array's integers as signed.
                typecode = numerics[T].lower()

            # Otherwise, we can simply lookup the typecode and use that one.
            else:
                typecode = numerics[T]

            # Create an _array using the typecode that we determined so that it can
            # be decoded and then returned to the caller.
            res = _array.array(typecode)

            # If our _array's itemsize doesn't match the element size that we expected,
            # then we need to warn the user that something fucked up and that we're
            # hijacking the array decoding with our own hardcoded unsigned length.
            cb = lnumerics[T]
            if res.itemsize != cb:
                logging.warning(u"{:s}.array({:#x}{:s}) : Refusing to decode array at address {:#x} using the array size ({:+d}) identified for DT_TYPE ({:#x}) due to the size of the DT_TYPE ({:#x}) not corresponding to the desired element size ({:+d}).".format('.'.join([__name__, cls.__name__]), ea, u", {:s}".format(utils.string.kwargs(length)) if length else '', ea, res.itemsize, T, T, cb))

                # Reconstruct the array but with the expected element size.
                try:
                    res = _array.array(utils.get_array_typecode(cb, 1))

                # If we can't use the typecode determined by the element size, then
                # just assume that the elements are just individual bytes.
                except ValueError:
                    res = _array.array(utils.get_array_typecode(1))

            # Get the number of elements for our array, and use it to read our data
            # from the database. Then we can use the data to initialize the _array
            # that we're going to return to the user.
            data = read(ea, count * cb)
            res.fromstring(data) if sys.version_info.major < 3 else res.frombytes(data)

            # Validate the _array's length so that we can warn the user if it's wrong.
            if len(res) != count:
                logging.warning(u"{:s}.array({:#x}{:s}) : The decoded array length ({:d}) is different from the expected length ({:d}).".format('.'.join([__name__, cls.__name__]), ea, u", {:s}".format(utils.string.kwargs(length)) if length else '', len(res), count))
            return res

        # If the "type" parameter was provided, then resolve that type into the
        # flags and DT_TYPE that we will need.
        if 'type' in length:
            F, tid, total = interface.typemap.resolve(length['type'])

            # If we were given an array in the "type" parameter, then reassign
            # that back into the "length" parameter so it can be used later.
            if isinstance(length['type'], builtins.list):
                _, count = length['type']
                length.setdefault('length', count)

        # Otherwise we extract the flags and DT_TYPE directly from the address.
        else:
            F, total = type.flags(ea), idaapi.get_item_size(ea)
            tid = type.structure.id(ea) if type.flags(ea, idaapi.DT_TYPE) == FF_STRUCT else idaapi.BADADDR

        # Set the array's length if it hasn't been determined yet.
        if not operator.contains(length, 'length'):
            length['length'] = type.array.length(ea)

        # Now that we have the flags and the type, we can use it to determine
        # how we need to decode the array. Since there's no utilities or
        # anything for performing these conversions in minsc, we'll need to
        # handle all of the element types ourselves by explicitly handling
        # each supported case.
        T = idaapi.as_uint32(F & idaapi.DT_TYPE)
        numerics, lnumerics = numeric_lookup_tables()

        # If this is a string-literal, then we need to figure out the element
        # size in order to figure out which character width to use.
        if T in {FF_STRLIT}:
            elesize = idaapi.get_full_data_elsize(ea, F)

            # Python's "u" typecode for their _array can actually change sizes. So
            # we have no choice here other than to just use the integer typecodes
            # for both 16-bit and 32-bit wide-character strings.
            strings = { 1: 'c', 2: utils.get_array_typecode(2), 4: utils.get_array_typecode(4) }
            t = strings[elesize]

            # Now we need to fix the value for T so that it corresponds to its
            # element size by checking the lnumerics array. Afterwards we can
            # simply decode it as normal.
            T = builtins.next(ff for ff, size in lnumerics.items() if size == elesize)
            return decode_array(ea, T, length['length'], numerics, lnumerics)

        # If we found a structure at this address, then we'll simply take its
        # length and use it to create a structure for each individual element.
        elif T in {FF_STRUCT}:
            cb = _structure.size(tid)
            # FIXME: this math doesn't work with dynamically sized structures (of course)
            count = length.get('length', math.trunc(math.ceil(float(total) / cb)))
            return [ cls.structure(ea + index * cb, identifier=tid) for index in builtins.range(count) ]

        # If the DT_TYPE was found in our numerics dictionary, then we're able
        # to use a native _array with the decode_array closure.
        elif T in numerics:
            return decode_array(ea, T, length['length'], numerics, lnumerics)

        # If the DT_TYPE was found in our lnumerics (long) dictionary, then use
        # that to figure out the element size, and read each integer as a list
        # due there being no native _array type.
        elif T in lnumerics:
            cb, total = lnumerics[T], idaapi.get_item_size(ea)
            # FIXME: Instead of returning the signed version of an integer, we
            #        need to return IDA's signed representation of the integer
            #        so that it directly corresponds to the user's view.
            Fgetinteger = get.signed if F & idaapi.FF_SIGN == idaapi.FF_SIGN else get.unsigned
            count = length.get('length', math.trunc(math.ceil(float(total) / cb)))
            return [ Fgetinteger(ea + index * cb, cb) for index in builtins.range(count) ]

        # Otherwise the DT_TYPE is unsupported, and we don't have a clue on how
        # this should be properly decoded...
        raise E.UnsupportedCapability(u"{:s}.array({:#x}{:s}) : Unknown DT_TYPE found in flags at address {:#x}. The flags {:#x} have the `idaapi.DT_TYPE` as {:#x}.".format('.'.join([__name__, cls.__name__]), ea, u", {:s}".format(utils.string.kwargs(length)) if length else '', ea, F, T))

    @utils.multicase()
    @classmethod
    def string(cls, **length):
        '''Return the array at the current address as a string.'''
        address, selection = ui.current.address(), ui.current.selection()
        if 'length' in length or operator.eq(*(internal.interface.address.head(ea, silent=True) for ea in selection)):
            return cls.string(address, **length)
        return cls.string(selection, **length)
    @utils.multicase(bounds=tuple)
    @classmethod
    def string(cls, bounds, **length):
        '''Return the array described by the specified `bounds` as a string.'''
        widthtype = {idaapi.STRWIDTH_1B: 1, idaapi.STRWIDTH_2B: 2, idaapi.STRWIDTH_4B: 4}

        # Similar to the get.string function, we're need to figure out the string
        # type to calculate what the string length means for the given bounds.
        if any(item in length for item in ['strtype', 'type']):
            res = builtins.next(length[item] for item in ['strtype', 'type'] if item in length)
            width_t, length_t = res if isinstance(res, (builtins.list, builtins.tuple)) else (res, 0)

        # If we didn't get one, then we actually figure it out by applying the
        # default string character width from the database. We're explicitly
        # ignoring the prefix here so the user has to explicitly specify it.
        else:
            inf = config.info.strtype if idaapi.__version__ < 7.2 else idaapi.inf_get_strtype()
            width_t, length_t = widthtype.get(inf & idaapi.STRWIDTH_MASK, 1), 0

        # Now we have the character width and the size of the length prefix size. So we
        # take the difference between our bounds and subtract the layout length from it.
        distance = operator.sub(*reversed(sorted(bounds)))
        if length_t > distance:
            logging.warning("{:s}.string({!s}{:s}) : Attempting to apply a string with a prefix length ({:d}) that is larger than the given boundaries ({:s}).".format('.'.join([__name__, cls.__name__]), bounds, u", {!s}".format(utils.string.kwargs(length)) if length else '', length_t, bounds))
        leftover = distance - length_t if distance > length_t else 0

        # That was it, we can now just use the leftover bytes to calculate our length,
        # assigned it into our kwargs, and chain to the real get.string functionality.
        ea, _ = bounds
        length.setdefault('length', math.trunc(math.ceil(leftover / width_t)))
        return cls.string(ea, **length)
    @utils.multicase(ea=six.integer_types)
    @classmethod
    def string(cls, ea, **length):
        """Return the array at the address specified by `ea` as a string.

        If an integer `length` is provided, then use it explicitly as the string's length when reading.
        If an integer `strtype` is provided, then use it as the string's character width when reading.
        If a tuple `strtype` is specified, then the first item is the character width and the second is the size of the length prefix when reading.
        """

        # For older versions of IDA, we get the strtype from the opinfo
        if idaapi.__version__ < 7.0:
            res = address.head(ea)
            ti, F = idaapi.opinfo_t(), type.flags(res)
            strtype = ti.strtype if idaapi.get_opinfo(res, 0, F, ti) else idaapi.BADADDR

            # and cast the result from idaapi.get_str_type_code to an integer
            get_str_type_code = utils.fcompose(idaapi.get_str_type_code, six.byte2int)

        # Fetch the string type at the given address using the newer API
        else:
            strtype = idaapi.get_str_type(address.head(ea))
            get_str_type_code = idaapi.get_str_type_code

        # Define some lookup tables that we'll use to figure out the lengths.
        widthtype = {1: idaapi.STRWIDTH_1B, 2: idaapi.STRWIDTH_2B, 4: idaapi.STRWIDTH_4B}
        lengthtype = {0: idaapi.STRLYT_TERMCHR, 1: idaapi.STRLYT_PASCAL1, 2: idaapi.STRLYT_PASCAL2, 4: idaapi.STRLYT_PASCAL4}

        # If a strtype was provided in the parameters, then convert it into a proper
        # string typecode so that the logic which follows will still work.
        if any(item in length for item in ['strtype', 'type']):

            # Extract the strtype that the user gave us whilst ensuring that we remove
            # the items out of the parameters since we later pass them to `get.array`.
            res = builtins.next((length.pop(item) for item in ['strtype', 'type'] if item in length))
            width_t, length_t = res if isinstance(res, (builtins.list, builtins.tuple)) else (res, 0)

            # Now that we've unpacked the string width and length prefix size from the
            # parameter, we can recombine them into a strtype code.
            strtype = (lengthtype[length_t] << idaapi.STRLYT_SHIFT) & idaapi.STRLYT_MASK
            strtype|= widthtype[width_t] & idaapi.STRWIDTH_MASK

            # Since the user gave us an explicit type, we need to update the keywords
            # which get passed to `get.array` so that each element is of the correct width.
            length['type'] = int, width_t

        # If we weren't given a strtype, then we still need to figure out what the default
        # is that was set in the database. This way we can actually fall back to something.
        else:
            inf = config.info.strtype if idaapi.__version__ < 7.2 else idaapi.inf_get_strtype()
            strwidth_t = inf & idaapi.STRWIDTH_MASK
            default_width = builtins.next((item for item, value in widthtype.items() if value == strwidth_t), 1)

        # If no string was found, then try to treat it as a plain old array
        # XXX: idaapi.get_str_type() seems to return 0xffffffff on failure instead of idaapi.BADADDR
        if strtype in {idaapi.BADADDR, 0xffffffff}:
            res = cls.array(ea, **length)

            # Warn the user what we're doing before we start figuring out
            # the element size of the string.
            if isinstance(res, _array.array):
                logging.warning(u"{:s}.string({:#x}{:s}) : Unable to guess the string type for address {:#x}. Reading it as an array of {:d}-byte sized integers and converting it to a string instead.".format('.'.join([__name__, cls.__name__]), ea, u", {:s}".format(utils.string.kwargs(length)) if length else '', ea, res.itemsize))

            # If we were unable to retrieve an _array.array, then it's likely because the address
            # is defined as a structure or a weird size. To fix it, we will set the type to the
            # default character width, warn the user that we're ignoring IDA, and try it again.
            else:
                logging.warning(u"{:s}.string({:#x}{:s}) : The data at address {:#x} is using a non-integral type and will be treated as an array of {:d}-byte sized characters.".format('.'.join([__name__, cls.__name__]), ea, u", {:s}".format(utils.string.kwargs(length)) if length else '', ea, default_width))
                length['type'] = int, default_width
                res = cls.array(ea, **length)

            # This really should be an assertion error or really a "unit-test" for cls.array,
            # because we _absolutely_ should have gotten an _array.array from cls.array.
            if not isinstance(res, _array.array):
                raise E.DisassemblerError(u"{:s}.string({:#x}{:s}) : There was a failure while trying to read the data at address {:#x} as an array of integers ({!s}).".format('.'.join([__name__, cls.__name__]), ea, u", {:s}".format(utils.string.kwargs(length)) if length else '', ea, res.__class__))

            # We can't figure out the shift.. So, since that's a dead end we have to assume that
            # the terminator is a null byte. Since we're already guessing, use the widthtype
            # that corresponds to our array itemsize whilst falling back to the default.
            sentinels, sl = '\0', idaapi.STRLYT_TERMCHR << idaapi.STRLYT_SHIFT
            sw = widthtype[res.itemsize if res.itemsize in widthtype else default_width]

            # FIXME: We should probably figure out the default codec for the character width here.
            encoding = idaapi.encoding_from_strtype(idaapi.STRENC_DEFAULT)
            decoder = None

        # Otherwise we can extract the string's characteristics directly from the strtype code.
        else:
            # Get the terminal characters that can terminate the string.
            sentinels = idaapi.get_str_term1(strtype) + idaapi.get_str_term2(strtype)

            # Extract the fields out of the string type code.
            res = get_str_type_code(strtype)
            sl, sw = res & idaapi.STRLYT_MASK, res & idaapi.STRWIDTH_MASK

            # Get the string encoding and look it up in our available codecs. If we can't find
            # it, then that's okay because we'll fall-back to one of the UTF-XX encodings.
            encoding = idaapi.encoding_from_strtype(strtype)

            try:
                decoder = functools.partial(codecs.lookup(encoding).decode, errors='replace')
            except LookupError:
                decoder = None
            finally:
                if not decoder:
                    logging.warning(u"{:s}.string({:#x}{:s}) : Due to the string at {:#x} being encoded with an unknown encoding ({:s}), the encoding will be determined based on the character size ({:d}).".format('.'.join([__name__, cls.__name__]), ea, u", {:s}".format(utils.string.kwargs(length)) if length else '', ea, encoding, {idaapi.STRWIDTH_1B: 1, idaapi.STRWIDTH_2B: 2, idaapi.STRWIDTH_4B: 4}.get(sw, -1)))

        # Figure out how the STRLYT field shifts and terminates the string.
        if sl == idaapi.STRLYT_TERMCHR << idaapi.STRLYT_SHIFT:
            shift, fterminate = 0, operator.methodcaller('rstrip', sentinels)
        elif sl == idaapi.STRLYT_PASCAL1 << idaapi.STRLYT_SHIFT:
            shift, fterminate = 1, utils.fidentity
        elif sl == idaapi.STRLYT_PASCAL2 << idaapi.STRLYT_SHIFT:
            shift, fterminate = 2, utils.fidentity
        elif sl == idaapi.STRLYT_PASCAL4 << idaapi.STRLYT_SHIFT:
            shift, fterminate = 4, utils.fidentity
        else:
            raise E.UnsupportedCapability(u"{:s}.string({:#x}{:s}) : Unsupported STRLYT({:d}) found in string at address {:#x}.".format('.'.join([__name__, cls.__name__]), ea, u", {:s}".format(utils.string.kwargs(length)) if length else '', sl, ea))

        # Figure out how the STRWIDTH field affects the string.
        if sw == idaapi.STRWIDTH_1B:
            cb, fdecode = 1, utils.fcompose(decoder, operator.itemgetter(0)) if decoder else operator.methodcaller('decode', 'utf-8', 'replace')
        elif sw == idaapi.STRWIDTH_2B:
            cb, fdecode = 2, utils.fcompose(decoder, operator.itemgetter(0)) if decoder else operator.methodcaller('decode', 'utf-16', 'replace')
        elif sw == idaapi.STRWIDTH_4B:
            cb, fdecode = 4, utils.fcompose(decoder, operator.itemgetter(0)) if decoder else operator.methodcaller('decode', 'utf-32', 'replace')
        else:
            raise E.UnsupportedCapability(u"{:s}.string({:#x}{:s}) : Unsupported STRWIDTH({:d}) found in string at address {:#x}.".format('.'.join([__name__, cls.__name__]), ea, u", {:s}".format(utils.string.kwargs(length)) if length else '', sw, ea))
        type = int, cb

        # If we don't need to shift our address, then just trust get.array.
        if not shift:
            res = cls.array(ea + shift, **length)

        # Otherwise use our length and the string width to figure out the
        # boundaries of the array and then we can read it.
        else:
            left, right = ea + shift, ea + shift + cb * cls.unsigned(ea, shift)
            res = cls.array((left, right), type)

        # Convert it to a string and then process it with the callables we determined.
        data = res.tostring() if sys.version_info.major < 3 else res.tobytes()
        return fterminate(fdecode(data))
    @utils.multicase()
    @classmethod
    def structure(cls):
        '''Return a dictionary of ctypes for the ``structure_t`` that is applied to the current address.'''
        return cls.structure(ui.current.address())
    @utils.multicase(ea=six.integer_types)
    @classmethod
    def structure(cls, ea):
        '''Return a dictionary of ctypes for the ``structure_t`` that is applied to the address `ea`.'''
        sid = type.structure.id(ea)
        return cls.structure(ea, sid)
    @utils.multicase(ea=six.integer_types, sptr=idaapi.struc_t)
    @classmethod
    def structure(cls, ea, sptr):
        '''Return a dictionary of ctypes for the ``structure_t`` identified by `sptr` at the address `ea`.'''
        return cls.structure(ea, sptr.id)
    @utils.multicase(ea=six.integer_types, name=six.string_types)
    @classmethod
    def structure(cls, ea, name):
        '''Return a dictionary of ctypes for the ``structure_t`` with the specified `name` at the address `ea`.'''
        st = _structure.by(name)
        return cls.structure(ea, st)
    @utils.multicase(ea=six.integer_types, type=_structure.structure_t)
    @classmethod
    def structure(cls, ea, type):
        '''Return a dictionary of ctypes for the ``structure_t`` specified by `type` at the address `ea`.'''
        return cls.structure(ea, type.id)
    @utils.multicase(ea=six.integer_types, identifier=six.integer_types)
    @classmethod
    def structure(cls, ea, identifier):
        '''Return a dictionary of ctypes for the ``structure_t`` with the specified `identifier` at the address `ea`.'''
        ea = interface.address.within(ea)

        # FIXME: consolidate this conversion into an interface or something
        st = _structure.by_identifier(identifier, offset=ea)
        typelookup = {
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

            # FIXME: add support for string types
        }

        res = {}
        for m in st.members:
            t, val = m.type, read(m.offset, m.size) or b''

            # try and lookup the individual type + size
            try:
                ct = typelookup[t]

            # either we don't support it, or it's an array
            except (TypeError, KeyError):

                # if it's an array, then unpack the count. otherwise we'll use a
                # count of -1 so that we can tell ctypes to not actually create
                # the type as an array. we can't use 0 here because ctypes
                # recognizes 0-length arrays.
                ty, count = t if isinstance(t, builtins.list) else (t, -1)

                # check that we really are handling an array, and lookup its type
                # to build a ctype with its count
                if isinstance(t, builtins.list) and operator.contains(typelookup, ty):
                    t = typelookup[ty]
                    ct = t if count < 0 else (t * count)

                # if our type is a string type, then we can simply make a ctype for it
                elif ty in {chr, str}:
                    ct = ctypes.c_char if count < 0 else (ctypes.c_char * count)

                # otherwise we have no idea what ctype we can use for this, so skip it
                # by creating a buffer for it
                else:
                    logging.warning(u"{:s}.structure({:#x}, ...) : Using buffer with size {:+#x} for member #{:d} ({:s}) due to unsupported type {!s}.".format('.'.join([__name__, cls.__name__]), ea, m.size, m.index, m.fullname, ty if count < 0 else [ty, count]))
                    ct = None

            # finally we can add the member to our result by creating a buffer for it
            res[m.name] = val if any(item is None for item in [ct, val]) else ctypes.cast(ctypes.pointer(ctypes.c_buffer(val)), ctypes.POINTER(ct)).contents
        return res
    struc = struct = utils.alias(structure, 'get')

    class switch(object):
        """
        Function for fetching an instance of a ``switch_t`` from a given address.
        Despite this being a namespace, by default it is intended to be used
        as a function against any known component of a switch. It will then
        return a class that allows one to query the different attributes of
        an ``idaapi.switch_info_t``.

        This namespace can be used as in the following example::

            > sw = database.get.switch(ea)
            > print( sw )

        """
        @classmethod
        def __of_label__(cls, ea):
            F, get_switch_info = type.flags(ea), idaapi.get_switch_info_ex if idaapi.__version__ < 7.0 else idaapi.get_switch_info

            # Verify that the label at the specified address has an actual name.
            # We can then use its address to grab all of the data references to it.
            if idaapi.has_dummy_name(F) or idaapi.has_user_name(F):
                drefs = (ref for ref in xref.data_up(ea))

                # With the data references, we need need to walk up one more step
                # and grab all types of references to it while looking for a switch.
                refs = (ref for ref in itertools.chain(*map(xref.up, drefs)) if get_switch_info(ref) is not None)

                # Now we'll just grab the very first reference we found. If we
                # got an address, then use it to grab the switch_info_t we want.
                ref = builtins.next(refs, None)
                si = None if ref is None else get_switch_info(ref)

            # Without a label, there's nothing we can do to find the switch_info_t.
            else:
                si = None

            # If we didn't find a switch_info_t, then raise a warning. Otherwise
            # the only thing left to do is to wrap it up for the user and return it.
            if si is None:
                switch_t = idaapi.switch_info_ex_t if idaapi.__version__ < 7.0 else idaapi.switch_info_t
                raise E.MissingTypeOrAttribute(u"{:s}({:#x}) : Unable to instantiate a `{:s}` at the target label for the given address ({:#x}).".format('.'.join([__name__, 'type', cls.__name__]), ea, switch_t.__name__, ea))
            return interface.switch_t(si)

        @classmethod
        def __of_array__(cls, ea):
            get_switch_info = idaapi.get_switch_info_ex if idaapi.__version__ < 7.0 else idaapi.get_switch_info

            # Grab all of the upward references to the array at the given address
            # that can give us an actual switch_info_t.
            refs = (ea for ea in xref.up(ea) if get_switch_info(ea) is not None)

            # Then we can grab the first one and use it. If we didn't get a valid
            # reference, then we're not going to get a valid switch.
            ref = builtins.next(refs, None)
            if ref is None:
                si = None

            # We have an address, so now we can just straight-up snag the switch.
            else:
                si = get_switch_info(ref)

            # If we were unable to get a switch, then just raise an exception. If we
            # did grab it, however, then we just need to wrap it up and then return.
            if si is None:
                switch_t = idaapi.switch_info_ex_t if idaapi.__version__ < 7.0 else idaapi.switch_info_t
                raise E.MissingTypeOrAttribute(u"{:s}({:#x}) : Unable to instantiate a `{:s}` using the array at the given address ({:#x}).".format('.'.join([__name__, 'type', cls.__name__]), ea, switch_t.__name__, ea))
            return interface.switch_t(si)

        @classmethod
        def __of_address__(cls, ea):
            get_switch_info = idaapi.get_switch_info_ex if idaapi.__version__ < 7.0 else idaapi.get_switch_info

            # Try and get a switch from the given address. If it worked, then
            # we just need to wrap it up nicely for them to use.
            si = get_switch_info(ea)
            if si is not None:
                return interface.switch_t(si)

            # Otherwise, we iterate through all of the address' downward
            # references to see if any valid candidates can be derived.
            for ref in xref.down(ea):
                found = not (get_switch_info(ref) is None)

                # If we actually grabbed the switch, then the current reference
                # actually is our only candidate and we should use it.
                if found:
                    candidates = (item for item in [ref])

                # Otherwise if the reference is pointing to data, then treat
                # it an array where we need to follow the downward references.
                elif type.is_data(ref):
                    items = (case for case in xref.down(ref))
                    candidates = (label for label in itertools.chain(*map(xref.up, items)) if get_switch_info(label))

                # Otherwise this must be code and so we'll check any of its
                # upward references to derive the necessary candidates.
                elif not found:
                    candidates = (label for label in xref.up(ref) if get_switch_info(label))

                # Grab the first location from our available candidates, and
                # try and get a switch_info_t using it.
                location = builtins.next(candidates, None)
                si = None if location is None else get_switch_info(location)

                # If we did grab a switch_info_t, then all we have to do is to
                # simply wrap it up before we can return it to the user.
                if si is not None:
                    return interface.switch_t(si)
                continue

            # If the loop exhaused all of the references for the given address,
            # then we didn't find shit and so we need to let the user know.
            switch_t = idaapi.switch_info_ex_t if idaapi.__version__ < 7.0 else idaapi.switch_info_t
            raise E.MissingTypeOrAttribute(u"{:s}({:#x}) : Unable to instantiate a `{:s}` using the branch instruction at the given address ({:#x}).".format('.'.join([__name__, 'type', cls.__name__]), ea, switch_t.__name__, ea))

        @classmethod
        def __of_block__(cls, ea):
            if not function.within(ea):
                switch_t = idaapi.switch_info_ex_t if idaapi.__version__ < 7.0 else idaapi.switch_info_t
                raise E.MissingTypeOrAttribute(u"{:s}({:#x}) : Unable to instantiate a `{:s}` using the given address ({:#x}) due to it not being within a function.".format('.'.join([__name__, 'type', cls.__name__]), ea, switch_t.__name__, ea))
            bounds = function.block(ea)

            # Now that we have the block, grab the last address as it could be
            # a branch that enters the switch, and feed it back into another method.
            left, right = bounds
            last = address.prev(right)
            return cls.__of_address__(last)

        @utils.multicase()
        def __new__(cls):
            '''Return the switch that is referenced at the current address.'''
            return cls(ui.current.address())
        @utils.multicase(ea=six.integer_types)
        def __new__(cls, ea):
            '''Return the switch that is referenced by the address at `ea`.'''
            ea = interface.address.within(ea)

            # Try literally everything we can with the specifeid address in order to
            # traverse to the branch instruction that is used by the switch.
            try:
                return cls.__of_address__(ea)
            except E.MissingTypeOrAttribute:
                pass
            try:
                return cls.__of_array__(ea)
            except E.MissingTypeOrAttribute:
                pass
            try:
                return cls.__of_label__(ea)
            except E.MissingTypeOrAttribute:
                pass
            try:
                return cls.__of_block__(ea)
            except E.MissingTypeOrAttribute:
                pass

            # Nope. Absolutely nothing we tried actually worked and we need to give up.
            switch_t = idaapi.switch_info_ex_t if idaapi.__version__ < 7.0 else idaapi.switch_info_t
            raise E.MissingTypeOrAttribute(u"{:s}({:#x}) : Unable to determine how to instantiate a `{:s}` using the information at the given address ({:#x}).".format('.'.join([__name__, 'type', cls.__name__]), ea, switch_t.__name__, ea))

