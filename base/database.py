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

import functools, operator, itertools
import sys, os, logging, bisect
import math, array as _array, fnmatch, re, time, datetime

import function, segment, ui
import structure as _structure
import idaapi, idc, internal
from internal import utils, interface, exceptions as E

## properties
def here():
    '''Return the current address.'''
    return ui.current.address()
h = utils.alias(here)

@utils.multicase()
def has():
    '''Return true if the current address is within the bounds of the database.'''
    return has(ui.current.address())
@utils.multicase(ea=internal.types.integer)
def has(ea):
    '''Return true if address `ea` is within the bounds of the database.'''
    left, right = information.bounds()
    return left <= ea < right
@utils.multicase(name=internal.types.string)
def has(name, *suffix):
    '''Return true if a symbol with the specified `name` is defined within the database.'''
    res = (name,) + suffix
    string = interface.tuplename(*res)
    ea = idaapi.get_name_ea(idaapi.BADADDR, utils.string.to(string))
    return ea != idaapi.BADADDR
contains = within = utils.alias(has)

def top():
    '''Return the very lowest address within the database.'''
    ea, _ = information.bounds()
    return ea
def bottom():
    '''Return the very highest address within the database.'''
    _, ea = information.bounds()
    return ea

class information(object):
    """
    This namespace contains various read-only properties about the
    database. This includes things such as the database boundaries,
    its filename, the path to the generated database, etc. Some tools
    for determining the type of the binary are also included.
    """

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

    @utils.multicase()
    @classmethod
    def lflags(cls):
        '''Return the value of the ``idainfo.lflags`` field from the database.'''
        return interface.database.flags()
    @utils.multicase(mask=internal.types.integer)
    @classmethod
    def lflags(cls, mask):
        '''Return the value of the ``idainfo.lflags`` field from the database with the specified `mask`.'''
        return interface.database.flags(mask)
    @utils.multicase(mask=internal.types.integer, value=internal.types.integer)
    @classmethod
    def lflags(cls, mask, value):
        '''Set the ``idainfo.lflags`` with the provided `mask` from the database to the specified `value`.'''
        result = interface.database.flags()
        if not interface.database.setflags(mask, value):
            raise E.DisassemblerError(u"{:s}.lflags({:#x}, {:#x}) : Unable to modify the flags in idainfo.lflags ({:#x} & {:#x}) to the specified value ({:s}).".format('.'.join([__name__, cls.__name__]), result, mask, "{:#x} & {:#x}".format(value, mask) if value & ~mask else "{:#x}".format(value)))
        return result

    @classmethod
    def filename(cls):
        '''Return the filename that the database was built from.'''
        return interface.database.filename()

    @classmethod
    def idb(cls):
        '''Return the full path to the database.'''
        return interface.database.idb()
    database = utils.alias(idb, 'information')

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
        return interface.database.path()
    @utils.multicase(pathname=internal.types.string)
    @classmethod
    def path(cls, pathname, *components):
        '''Return an absolute path composed of the provided `pathname` and any additional `components` relative to the directory containing the database.'''
        base = interface.database.path()
        return os.path.join(base, pathname, *components)

    @classmethod
    def baseaddress(cls):
        '''Return the baseaddress of the database.'''
        return interface.database.imagebase()

    @classmethod
    def readonly(cls):
        '''Return whether the database is read-only or not.'''
        if idaapi.__version__ < 7.0:
            raise E.UnsupportedVersion(u"{:s}.readonly() : This function is only supported on versions of IDA 7.0 and newer.".format('.'.join([__name__, cls.__name__])))
        return interface.database.readonly()
    is_readonly = utils.alias(readonly, 'information')

    @classmethod
    def shared(cls):
        '''Return whether the database is a shared-object or not.'''
        if idaapi.__version__ < 7.0:
            raise E.UnsupportedVersion(u"{:s}.shared() : This function is only supported on versions of IDA 7.0 and newer.".format('.'.join([__name__, cls.__name__])))
        return True if cls.lflags(idaapi.LFLG_IS_DLL) else False
    is_sharedobject = is_shared = is_dll = utils.alias(shared, 'information')

    @classmethod
    def kernel(cls):
        '''Return whether the database is using a kernelmode address space or not.'''
        if idaapi.__version__ < 7.0:
            raise E.UnsupportedVersion(u"{:s}.kernel() : This function is only supported on versions of IDA 7.0 and newer.".format('.'.join([__name__, cls.__name__])))
        return True if cls.lflags(idaapi.LFLG_KERNMODE) else False
    is_kernelspace = is_kernel = utils.alias(kernel, 'information')

    @utils.multicase()
    @classmethod
    def filetype(cls):
        '''Return the file type identified by the loader when creating the database.'''
        return interface.database.filetype()
    @utils.multicase(filetype_t=internal.types.integer)
    @classmethod
    def filetype(cls, filetype_t):
        '''Set the file type identified by the loader to the specified `filetype_t`.'''
        result = interface.database.filetype()
        if not interface.database.setfiletype(filetype_t):
            raise E.DisassemblerError(u"{:s}.filetype({:#x}) : Unable to set value for idainfo.filetype to the specified value ({:#x}).".format('.'.join([__name__, cls.__name__]), filetype_t, filetype_t))
        return result
    @utils.multicase(FT_=internal.types.string)
    @classmethod
    def filetype(cls, FT_):
        '''Set the file type identified by the loader to the value for the string `FT_`.'''
        prefix, choice = 'FT_', FT_.upper()
        candidates = {prefix + choice, choice}

        # Grab all of our available choices from the idc module since they're not defined anywhere else.
        filtered = ((name, getattr(idc, name)) for name in dir(idc) if name.startswith(prefix))
        choices = {item : value for item, value in filtered if isinstance(value, internal.types.integer)}

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
        return interface.database.ostype()
    @utils.multicase(ostype_t=internal.types.integer)
    @classmethod
    def ostype(cls, ostype_t):
        '''Set the operating system type for the database to the specified `ostype_t`.'''
        result = interface.database.ostype()
        if not interface.database.setostype(ostype_t):
            raise E.DisassemblerError(u"{:s}.ostype({:#x}) : Unable to set value for idainfo.ostype to the specified value ({:#x}).".format('.'.join([__name__, cls.__name__]), ostype_t, ostype_t))
        return result
    @utils.multicase(OSTYPE_=internal.types.string)
    @classmethod
    def ostype(cls, OSTYPE_):
        '''Set the operating system type for the database to the value for the string `OSTYPE_`.'''
        prefix, choice = 'OSTYPE_', OSTYPE_.upper()
        candidates = {prefix + choice, choice}

        # Grab all of our available choices from the idc module since they're not defined anywhere else.
        filtered = ((name, getattr(idc, name)) for name in dir(idc) if name.startswith(prefix))
        choices = {item : value for item, value in filtered if isinstance(value, internal.types.integer)}

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
        return interface.database.apptype()
    @utils.multicase(apptype_t=internal.types.integer)
    @classmethod
    def apptype(cls, apptype_t):
        '''Set the application type for the database to the specified `apptype_t`.'''
        result = interface.database.apptype()
        if not interface.database.setapptype(apptype_t):
            raise E.DisassemblerError(u"{:s}.apptype({:#x}) : Unable to set value for idainfo.apptype to the specified value ({:#x}).".format('.'.join([__name__, cls.__name__]), apptype_t, apptype_t))
        return result
    @utils.multicase(APPT_=internal.types.string)
    @classmethod
    def apptype(cls, APPT_):
        '''Set the application type for the database to the value for the string `APPT_`.'''
        prefix, choice = 'APPT_', APPT_.upper()
        candidates = {prefix + choice, choice}

        # Grab all of our available choices from the idc module since they're not defined anywhere else.
        filtered = ((name, getattr(idc, name)) for name in dir(idc) if name.startswith(prefix))
        choices = {item : value for item, value in filtered if isinstance(value, internal.types.integer)}

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
        return interface.database.changecount()

    @classmethod
    def processor(cls):
        '''Return the name of the processor used by the database.'''
        if idaapi.__version__ < 7.0:
            raise E.UnsupportedVersion(u"{:s}.processor() : This function is only supported on versions of IDA 7.0 and newer.".format('.'.join([__name__, cls.__name__])))
        return interface.database.processor()

    @classmethod
    def compiler(cls):
        '''Return the compiler that was configured for the database.'''
        res = interface.database.compiler()
        if res is None:
            raise E.DisassemblerError(u"{:s}.processor() : Unable to fetch the value for the idainfo.cc attribute.".format('.'.join([__name__, cls.__name__])))
        return res

    @classmethod
    def version(cls):
        '''Return the version of the database.'''
        return interface.database.version()

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
        '''Return number of bits for the processor used by the database.'''
        return interface.database.bits()

    @classmethod
    def size(cls):
        '''Return the number of bytes used to represent an address in the database.'''
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
        '''Return the number of bits used to represent an address in the database.'''
        return 8 * cls.size()

    @classmethod
    def byteorder(cls):
        '''Return a string representing the byte-order used by integers in the database.'''
        return interface.database.byteorder()

    @classmethod
    def entry(cls):
        '''Return the first entry point for the database.'''
        return interface.database.entrypoint()

    @classmethod
    def margin(cls):
        '''Return the current margin position for the current database.'''
        return interface.database.margin()

    @classmethod
    def bounds(cls):
        '''Return the bounds of the current database in a tuple formatted as `(left, right)`.'''
        start, stop = interface.address.bounds()
        return interface.bounds_t(start, stop)

    @classmethod
    def created(cls):
        '''Return the date and time that the database was created.'''
        if idaapi.__version__ < 7.4:
            raise E.UnsupportedVersion(u"{:s}.created() : This function is only supported on versions of IDA 7.4 and newer.".format('.'.join([__name__, cls.__name__])))
        RIDX_ALT_CTIME = -2
        asize_t, root = idaapi.ea_pointer(), internal.netnode.get('Root Node')
        _, uval = asize_t.assign(RIDX_ALT_CTIME), asize_t.value()
        ts = internal.netnode.alt.get(root, uval)
        utc = builtins.type('timezone.utc', (datetime.tzinfo,), {k : v for k, v in itertools.chain([('__repr__', lambda self: 'utc')], [(attribute, lambda self, dt, value=value: value) for attribute, value in zip(['utcoffset', 'dst', 'tzname'], itertools.chain(2 * [datetime.timedelta(0)], ['UTC']))])})
        tzinfo = utc() if sys.version_info.major < 3 else datetime.timezone.utc
        return datetime.datetime.fromtimestamp(time.mktime(time.gmtime(ts)), tzinfo).astimezone()

    @classmethod
    def elapsed(cls):
        '''Return the number of seconds that the database has remained open.'''
        if idaapi.__version__ < 7.4:
            raise E.UnsupportedVersion(u"{:s}.elapsed() : This function is only supported on versions of IDA 7.4 and newer.".format('.'.join([__name__, cls.__name__])))
        RIDX_ALT_ELAPSED = -3
        asize_t, root = idaapi.ea_pointer(), internal.netnode.get('Root Node')
        _, uval = asize_t.assign(RIDX_ALT_ELAPSED), asize_t.value()
        return internal.netnode.alt.get(root, uval)

    @classmethod
    def opens(cls):
        '''Return the number of times that the database has been opened.'''
        if idaapi.__version__ < 7.4:
            raise E.UnsupportedVersion(u"{:s}.opened() : This function is only supported on versions of IDA 7.4 and newer.".format('.'.join([__name__, cls.__name__])))
        RIDX_ALT_NOPENS = -4
        asize_t, root = idaapi.ea_pointer(), internal.netnode.get('Root Node')
        _, uval = asize_t.assign(RIDX_ALT_NOPENS), asize_t.value()
        return internal.netnode.alt.get(root, uval)

    @classmethod
    def CRC32(cls):
        '''Return the CRC32 of the input file used for the current database.'''
        if idaapi.__version__ < 7.4:
            raise E.UnsupportedVersion(u"{:s}.CRC32() : This function is only supported on versions of IDA 7.4 and newer.".format('.'.join([__name__, cls.__name__])))
        RIDX_ALT_CRC32 = -5
        asize_t, root = idaapi.ea_pointer(), internal.netnode.get('Root Node')
        _, uval = asize_t.assign(RIDX_ALT_CRC32), asize_t.value()
        return internal.netnode.alt.get(root, uval)

    @classmethod
    def MD5(cls):
        '''Return the CRC32 of the input file used for the current database.'''
        if idaapi.__version__ < 7.4:
            raise E.UnsupportedVersion(u"{:s}.MD5() : This function is only supported on versions of IDA 7.4 and newer.".format('.'.join([__name__, cls.__name__])))
        RIDX_MD5 = 1302
        asize_t, root = idaapi.ea_pointer(), internal.netnode.get('Root Node')
        _, uval = asize_t.assign(RIDX_MD5), asize_t.value()
        return internal.netnode.sup.get(root, uval, type=memoryview).tobytes()

    @classmethod
    def SHA256(cls):
        '''Return the SHA256 of the input file used for the current database.'''
        if idaapi.__version__ < 7.4:
            raise E.UnsupportedVersion(u"{:s}.SHA256() : This function is only supported on versions of IDA 7.4 and newer.".format('.'.join([__name__, cls.__name__])))
        RIDX_SHA256 = 1349
        asize_t, root = idaapi.ea_pointer(), internal.netnode.get('Root Node')
        _, uval = asize_t.assign(RIDX_SHA256), asize_t.value()
        return internal.netnode.sup.get(root, uval, type=memoryview).tobytes()

config = info = information # XXX: ns alias

range = utils.alias(information.bounds, 'information')
filename, idb, module, path = utils.alias(information.filename, 'information'), utils.alias(information.idb, 'information'), utils.alias(information.module, 'information'), utils.alias(information.path, 'information')
path = utils.alias(information.path, 'information')
baseaddress = base = utils.alias(information.baseaddress, 'information')

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

        `address` or `ea` - Filter the functions by an address or a list of addresses
        `name` - Filter the functions by a name or a list of names
        `like` - Filter the function names according to a glob
        `regex` - Filter the function names according to a regular-expression
        `index` - Filter the functions by an index or a list of indices
        `mangled` - Filter the mangled function names according to a glob
        `decorated` - Match the functions using C++ name decorations
        `arguments` or `args` - Filter the functions by the argument count or a list of counts
        `typed` - Filter the functions for any that have type information applied to them
        `decompiled` - Filter the functions for any that have been decompiled
        `frame` - Filter the functions for any that contain a frame
        `problems` - Filter the functions for any that contain problems with their stack
        `library` - Filter the functions that any which were detected as a library function
        `wrapper` - Filter the functions that are flagged as wrappers (thunks)
        `lumina` - Filter the functions that were detected by Lumina
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
    __matcher__.combinator('name', utils.fcondition(utils.finstance(internal.types.string))(utils.fcompose(operator.methodcaller('lower'), utils.fpartial(utils.fpartial, operator.eq)), utils.fcompose(utils.fpartial(map, operator.methodcaller('lower')), internal.types.set, utils.fpartial(utils.fpartial, operator.contains))), interface.function.by_address, interface.function.name, operator.methodcaller('lower'))
    __matcher__.combinator('like', utils.fcompose(fnmatch.translate, utils.fpartial(re.compile, flags=re.IGNORECASE), operator.attrgetter('match')), interface.function.by_address, interface.function.name)
    __matcher__.combinator('regex', utils.fcompose(utils.fpartial(re.compile, flags=re.IGNORECASE), operator.attrgetter('match')), interface.function.by_address, interface.function.name)
    __matcher__.combinator('address', utils.fcondition(utils.finstance(internal.types.integer))(utils.fpartial(utils.fpartial, operator.eq), utils.fpartial(utils.fpartial, operator.contains)))
    __matcher__.alias('ea', 'address')
    __matcher__.combinator('index', utils.fcondition(utils.finstance(internal.types.integer))(utils.fpartial(utils.fpartial, operator.eq), utils.fpartial(utils.fpartial, operator.contains)), idaapi.get_func_num)
    __matcher__.combinator('mangled', utils.fcondition(utils.finstance(internal.types.string))(utils.fcompose(fnmatch.translate, utils.fpartial(re.compile, flags=re.IGNORECASE), operator.attrgetter('match')), utils.fcompose(utils.fcompose(operator.truth, utils.fpartial(utils.fpartial, operator.eq)), utils.fpartial(utils.fcompose, utils.string.to, idaapi.get_mangled_name_type, utils.fpartial(operator.ne, getattr(idaapi, 'MANGLED_UNKNOWN', 2))) if hasattr(idaapi, 'get_mangled_name_type') else utils.fpartial(utils.fcompose, utils.fmap(utils.fidentity, internal.declaration.demangle), utils.funpack(operator.ne)))), idaapi.get_true_name if idaapi.__version__ < 6.8 else idaapi.get_ea_name, utils.string.of)
    __matcher__.alias('decorated', 'mangled')
    __matcher__.combinator('arguments', utils.fcondition(utils.finstance(internal.types.integer))(utils.fpartial(utils.fpartial, operator.eq), utils.fpartial(utils.fpartial, operator.contains)), function.type, operator.methodcaller('get_nargs'))
    __matcher__.alias('args', 'arguments')
    __matcher__.mapping('typed', operator.truth, lambda ea: idaapi.get_tinfo2(ea, idaapi.tinfo_t()) if idaapi.__version__ < 7.0 else idaapi.get_tinfo(idaapi.tinfo_t(), ea))
    __matcher__.mapping('decompiled', operator.truth, function.type.decompiled)
    __matcher__.mapping('frame', operator.truth, function.type.frame)
    __matcher__.mapping('library', operator.truth, interface.function.by_address, operator.attrgetter('flags'), utils.fpartial(operator.and_, idaapi.FUNC_LIB))
    __matcher__.mapping('wrapper', operator.truth, interface.function.by_address, operator.attrgetter('flags'), utils.fpartial(operator.and_, idaapi.FUNC_THUNK))
    __matcher__.mapping('lumina', operator.truth, interface.function.by_address, operator.attrgetter('flags'), utils.fpartial(operator.and_, getattr(idaapi, 'FUNC_LUMINA', 0x10000)))
    __matcher__.boolean('tagged', lambda parameter, keys: operator.truth(keys) == parameter if isinstance(parameter, internal.types.bool) else operator.contains(keys, parameter) if isinstance(parameter, internal.types.string) else keys & internal.types.set(parameter), function.top, internal.tags.function.get, operator.methodcaller('keys'), internal.types.set)
    __matcher__.combinator('bounds', utils.fcondition(utils.finstance(interface.bounds_t))(operator.attrgetter('contains'), utils.fcompose(utils.funpack(interface.bounds_t), operator.attrgetter('contains'))))
    __matcher__.predicate('predicate', interface.function.by_address), __matcher__.alias('pred', 'predicate')

    if any(hasattr(idaapi, item) for item in ['is_problem_present', 'QueueIsPresent']):
        __matcher__.mapping('problems', operator.truth, utils.frpartial(function.type.problem, getattr(idaapi, 'PR_BADSTACK', 0xb)))

    if all(hasattr(idaapi, Fname) for Fname in ['tryblks_t', 'get_tryblks']):
        __matcher__.mapping('exceptions', operator.truth, interface.function.by_address, lambda fn: idaapi.get_tryblks(idaapi.tryblks_t(), fn), utils.fpartial(operator.ne, 0))

    # chunk matching
    #__matcher__.boolean('greater', operator.le, utils.fcompose(function.chunks, functools.partial(map, builtins.list, operator.itemgetter(-1)), max)), __matcher__.boolean('gt', operator.lt, utils.fcompose(function.chunks, functools.partial(map, builtins.list, operator.itemgetter(-1)), max))
    #__matcher__.boolean('less', operator.ge, utils.fcompose(function.chunks, functools.partial(map, builtins.list, operator.itemgetter(0)), min)), __matcher__.boolean('lt', operator.gt, utils.fcompose(function.chunks, functools.partial(map, builtins.list, operator.itemgetter(0)), min))

    # entry point matching
    __matcher__.boolean('greater', operator.le, utils.fidentity), __matcher__.boolean('gt', operator.lt, utils.fidentity)
    __matcher__.boolean('less', operator.ge, utils.fidentity), __matcher__.boolean('lt', operator.gt, utils.fidentity)

    def __new__(cls, *string, **type):
        '''Return the address of each of the functions within the database as a list.'''
        return [item for item in cls.iterate(*string, **type)]

    @utils.multicase()
    @classmethod
    def __iterate__(cls):
        '''Iterates through each of the functions within the current database.'''
        left, right = interface.address.bounds()

        # find first function chunk
        ch = idaapi.get_fchunk(left) or idaapi.get_next_fchunk(left)
        while ch and interface.range.start(ch) < right and (ch.flags & idaapi.FUNC_TAIL) != 0:
            ui.navigation.procedure(interface.range.start(ch))
            ch = idaapi.get_next_fchunk(interface.range.start(ch))

        # iterate through the rest of the functions in the database
        while ch and interface.range.start(ch) < right:
            ui.navigation.procedure(interface.range.start(ch))
            if interface.function.has(interface.range.start(ch)):
                yield interface.range.start(ch)
            ch = idaapi.get_next_func(interface.range.start(ch))
        return

    @utils.multicase(name=internal.types.string)
    @classmethod
    @utils.string.decorate_arguments('name')
    def iterate(cls, name):
        '''Iterate through the functions from the database that match the glob specified by `name`.'''
        return cls.iterate(like=name)
    @utils.multicase(bounds=interface.bounds_t)
    @classmethod
    def iterate(cls, bounds):
        '''Iterate through the functions from the database within the given `bounds`.'''
        return cls.iterate(predicate=operator.truth, bounds=bounds)
    @utils.multicase()
    @classmethod
    @utils.string.decorate_arguments('name', 'like', 'regex')
    def iterate(cls, **type):
        '''Iterate through the functions from the database that match the keywords specified by `type`.'''
        iterable = cls.__iterate__()
        for key, value in (type or {'predicate': utils.fconstant(True)}).items():
            iterable = cls.__matcher__.match(key, value, iterable)
        for item in iterable: yield item

    @utils.multicase(name=internal.types.string)
    @classmethod
    @utils.string.decorate_arguments('name')
    def list(cls, name):
        '''List the functions from the database that match the glob specified by `name`.'''
        return cls.list(like=name)
    @utils.multicase(bounds=interface.bounds_t)
    @classmethod
    def list(cls, bounds):
        '''List the functions from the database within the given `bounds`.'''
        return cls.list(predicate=operator.truth, bounds=bounds)
    @utils.multicase()
    @classmethod
    @utils.string.decorate_arguments('name', 'like', 'regex')
    def list(cls, **type):
        '''List the functions from the database that match the keywords specified by `type`.'''
        listable = []

        # Some utility functions for grabbing counts of function attributes
        Fcount_lvars = utils.fcompose(function.frame.lvars, utils.count)
        Fcount_avars = utils.fcompose(interface.function.typeinfo, operator.methodcaller('get_nargs')) if hasattr(idaapi.tinfo_t, 'get_nargs') else utils.fcompose(function.frame.args.iterate, utils.count)

        # Set some reasonable defaults here
        maxentry = top()
        maxaddr = minaddr = maxchunks = 0
        maxname = maxunmangled = chunks = marks = blocks = exits = 0
        lvars = avars = refs = 0

        # First pass through the list to grab the maximum lengths of the different fields
        for ea in cls.iterate(**type):
            func, _ = interface.function.by_address(ea), ui.navigation.procedure(ea)
            maxentry = max(ea, maxentry)

            unmangled, realname = interface.function.name(func), interface.name.get(ea)
            maxname = max(len(unmangled), maxname)
            maxunmangled = max(len(unmangled), maxunmangled) if not internal.declaration.mangledQ(realname) else maxunmangled

            bounds, items = interface.range.bounds(func), [interface.range.bounds(item) for item in interface.function.chunks(func)]
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
            func, decompiledQ = interface.function.by_address(ui.navigation.procedure(ea)), interface.node.aflags(ui.navigation.procedure(ea), getattr(idaapi, 'AFL_HR_DETERMINED', 0xc0000000))
            tags = internal.tags.function.get(ea)

            # any flags that might be useful
            ftagged = '-' if not tags else '*' if any(not item.startswith('__') for item in tags) else '+'
            ftyped = 'D' if function.type.decompiled(ea) else '-' if not interface.function.has_typeinfo(func) else 'T' if interface.node.aflags(ea, idaapi.AFL_USERTI) else 't'
            fframe = '?' if function.type.problem(ea, getattr(idaapi, 'PR_BADSTACK', 0xb)) else '-' if idaapi.get_frame(ea) else '^'
            fgeneral = 'J' if func.flags & idaapi.FUNC_THUNK else 'L' if func.flags & idaapi.FUNC_LIB else 'S' if func.flags & idaapi.FUNC_STATICDEF else 'F'
            flags = itertools.chain(fgeneral, fframe, ftyped, ftagged)

            # naming information
            unmangled, realname = interface.function.name(func), interface.name.get(ea)

            # chunks and boundaries
            chunks = [interface.range.bounds(item) for item in interface.function.chunks(func)]
            bounds = interface.range.bounds(func)

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

    @utils.multicase(name=internal.types.string)
    @classmethod
    @utils.string.decorate_arguments('name')
    def search(cls, name):
        '''Search through the functions within the database and return the first result that matches the glob specified by `name`.'''
        return cls.search(like=name)
    @utils.multicase()
    @classmethod
    @utils.string.decorate_arguments('name', 'like', 'regex')
    def search(cls, **type):
        '''Search through the functions within the database and return the first result matching the keywords specified by `type`.'''
        query_s = utils.string.kwargs(type)

        listable = [item for item in cls.iterate(**type)]
        if len(listable) > 1:
            messages = ((u"[{:d}] {:s}".format(i, interface.function.name(ea))) for i, ea in enumerate(listable))
            [ logging.info(msg) for msg in messages ]
            f = utils.fcompose(interface.function.by_address, interface.function.name)
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

    def __new__(cls, *string, **type):
        '''Return the boundaries for each of the segments within the database as a list.'''
        iterable = (item for item in segment.__iterate__(*string, **type))
        return [interface.range.bounds(item) for item in iterable]

    @utils.multicase(name=internal.types.string)
    @classmethod
    @utils.string.decorate_arguments('name')
    def list(cls, name):
        '''List the segments within the database that match the glob specified by `name`.'''
        return cls.list(like=name)
    @utils.multicase()
    @classmethod
    @utils.string.decorate_arguments('name', 'like', 'regex')
    def list(cls, **type):
        '''List the segments within the database that match the keywords specified by `type`.'''
        return segment.list(**type)

    @utils.multicase(name=internal.types.string)
    @classmethod
    @utils.string.decorate_arguments('name')
    def iterate(cls, name):
        '''Yield the boundary of each segment within the database that match the glob specified by `name`.'''
        return cls.iterate(like=name)
    @utils.multicase()
    @classmethod
    @utils.string.decorate_arguments('name', 'like', 'regex')
    def iterate(cls, **type):
        '''Yield the boundary of each segment within the database the match the keywords specified by `type`.'''
        for item in segment.__iterate__(**type):
            yield interface.range.bounds(item)
        return

    @utils.multicase(name=internal.types.string)
    @classmethod
    @utils.string.decorate_arguments('name')
    def search(cls, name):
        '''Search through the segments that match the glob `name` and return the first result.'''
        return cls.search(like=name)
    @utils.multicase()
    @classmethod
    @utils.string.decorate_arguments('name', 'like', 'regex')
    def search(cls, **type):
        '''Search through the segments within the database and return the first result matching the keywords specified by `type`.'''
        return segment.search(**type)

@utils.multicase()
def instruction():
    '''Return the instruction at the current address as a string.'''
    return instruction(ui.current.address())
@utils.multicase(ea=internal.types.integer)
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
@utils.multicase(ea=internal.types.integer)
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
    '''Return the bytes defined at the current selection or address.'''
    address, selection = ui.current.address(), ui.current.selection()
    if operator.eq(*(interface.address.head(ea) for ea in selection)):
        return read(address, interface.address.size(address))
    return read(selection)
@utils.multicase(ea=internal.types.integer)
def read(ea):
    '''Return the number of bytes associated with the address `ea`.'''
    return interface.address.read(ea, interface.address.size(ea))
@utils.multicase(ea=internal.types.integer, size=internal.types.integer)
def read(ea, size):
    '''Return `size` number of bytes from address `ea`.'''
    start, end = interface.address.within(ea, ea + size)
    return interface.address.read(ea, end - start)
@utils.multicase(bounds=interface.bounds_t)
def read(bounds):
    '''Return the bytes within the specified `bounds`.'''
    bounds = ea, _ = interface.bounds_t(*bounds)
    return interface.address.read(ea, bounds.size)

@utils.multicase(data=internal.types.bytes)
def write(data, **persist):
    '''Modify the database at the current address with the bytes specified in `data`.'''
    return write(ui.current.address(), data, **persist)
@utils.multicase(ea=internal.types.integer, data=internal.types.bytes)
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

        `address` or `ea` - Filter the symbols by an address or a list of addresses
        `name` - Filter the symbols by unmangled name or a list of unmangled names
        `unmangled` - Filter the unmangled symbol names according to a regular-expression
        `like` - Filter the symbol names according to a glob
        `bounds` - Filter the symbol names within the given boundaries
        `regex` - Filter the symbol names according to a regular-expression
        `index` - Filter the symbol according to an index or a list of indices
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
    __matcher__.combinator('address', utils.fcondition(utils.finstance(internal.types.integer))(utils.fpartial(utils.fpartial, operator.eq), utils.fpartial(utils.fpartial, operator.contains)), idaapi.get_nlist_ea)
    __matcher__.alias('ea', 'address')
    __matcher__.combinator('name', utils.fcondition(utils.finstance(internal.types.string))(utils.fcompose(operator.methodcaller('lower'), utils.fpartial(utils.fpartial, operator.eq)), utils.fcompose(utils.fpartial(map, operator.methodcaller('lower')), internal.types.set, utils.fpartial(utils.fpartial, operator.contains))), idaapi.get_nlist_name, internal.declaration.demangle)
    __matcher__.combinator('like', utils.fcompose(fnmatch.translate, utils.fpartial(re.compile, flags=re.IGNORECASE), operator.attrgetter('match')), idaapi.get_nlist_name, utils.string.of)
    __matcher__.combinator('regex', utils.fcompose(utils.fpartial(re.compile, flags=re.IGNORECASE), operator.attrgetter('match')), idaapi.get_nlist_name, utils.string.of)
    __matcher__.combinator('unmangled', utils.fcompose(utils.fpartial(re.compile, flags=re.IGNORECASE), operator.attrgetter('match')), idaapi.get_nlist_name, internal.declaration.demangle)
    __matcher__.alias('demangled', 'unmangled')
    __matcher__.mapping('function', interface.function.has, idaapi.get_nlist_ea)
    __matcher__.mapping('imports', utils.fpartial(operator.eq, idaapi.SEG_XTRN), idaapi.get_nlist_ea, idaapi.segtype)
    __matcher__.boolean('tagged', lambda parameter, keys: operator.truth(keys) == parameter if isinstance(parameter, internal.types.bool) else operator.contains(keys, parameter) if isinstance(parameter, internal.types.string) else keys & internal.types.set(parameter), idaapi.get_nlist_ea, lambda ea: internal.tags.function.get(ea) if interface.function.has(ea) else internal.tags.address.get(ea), operator.methodcaller('keys'), internal.types.set)
    __matcher__.mapping('typed', operator.truth, idaapi.get_nlist_ea, lambda ea: idaapi.get_tinfo2(ea, idaapi.tinfo_t()) if idaapi.__version__ < 7.0 else idaapi.get_tinfo(idaapi.tinfo_t(), ea))
    __matcher__.combinator('bounds', utils.fcondition(utils.finstance(interface.bounds_t))(operator.attrgetter('contains'), utils.fcompose(utils.funpack(interface.bounds_t, operator.attrgetter('contains')))), idaapi.get_nlist_ea)
    __matcher__.predicate('predicate', idaapi.get_nlist_ea), __matcher__.alias('pred', 'predicate')
    __matcher__.attribute('index')

    def __new__(cls, *string, **type):
        '''Return the names within the database as a list composed of tuples packed as `(address, name)`.'''
        return [(ea, name) for ea, name in cls.iterate(*string, **type)]

    @utils.multicase(string=internal.types.string)
    @classmethod
    @utils.string.decorate_arguments('string')
    def __iterate__(cls, string):
        return cls.__iterate__(like=string)
    @utils.multicase(bounds=interface.bounds_t)
    @classmethod
    def __iterate__(cls, bounds):
        return cls.__iterate__(predicate=operator.truth, bounds=bounds)
    @utils.multicase()
    @classmethod
    @utils.string.decorate_arguments('name', 'like', 'regex')
    def __iterate__(cls, **type):
        iterable = (idx for idx in builtins.range(idaapi.get_nlist_size()))
        for key, value in (type or {'predicate': utils.fconstant(True)}).items():
            iterable = cls.__matcher__.match(key, value, iterable)
        for item in iterable: yield item

    @utils.multicase(name=internal.types.string)
    @classmethod
    @utils.string.decorate_arguments('name')
    def iterate(cls, name):
        '''Iterate through the names from the database that match the glob specified by `name`.'''
        return cls.iterate(like=name)
    @utils.multicase(bounds=interface.bounds_t)
    @classmethod
    def iterate(cls, bounds):
        '''Iterate through the names from the database that match the glob specified by `name`.'''
        return cls.iterate(predicate=operator.truth, bounds=bounds)
    @utils.multicase()
    @classmethod
    @utils.string.decorate_arguments('name', 'like', 'regex')
    def iterate(cls, **type):
        '''Iterate through the names from the database that match the keywords specified by `type`.'''
        for idx in cls.__iterate__(**type):
            ea, name = idaapi.get_nlist_ea(idx), idaapi.get_nlist_name(idx)
            yield ea, utils.string.of(name)
        return

    @utils.multicase(name=internal.types.string)
    @classmethod
    @utils.string.decorate_arguments('name')
    def list(cls, name):
        '''List the names from the database that match the glob specified by `name`.'''
        return cls.list(like=name)
    @utils.multicase(bounds=interface.bounds_t)
    @classmethod
    def list(cls, bounds):
        '''List the names from the database within the given `bounds`.'''
        return cls.list(predicate=operator.truth, bounds=bounds)
    @utils.multicase()
    @classmethod
    @utils.string.decorate_arguments('name', 'like', 'regex')
    def list(cls, **type):
        '''List the names from the database that match the keywords specified by `type`.'''
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
            tags = internal.tags.function.get(ea) if interface.function.has(ea) else internal.tags.address.get(ea)

            # Any flags that could be useful
            ftype = 'I' if idaapi.segtype(ea) == idaapi.SEG_XTRN else '-' if t.unknown(ea) else 'C' if t.code(ea) else 'D' if t.data(ea) else '-'
            finitialized = '^' if t.initialized(ea) else '-'
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

    @utils.multicase(name=internal.types.string)
    @classmethod
    @utils.string.decorate_arguments('name')
    def search(cls, name):
        '''Search through the names within the database that match the glob `name` and return the first result.'''
        return cls.search(like=name)
    @utils.multicase()
    @classmethod
    @utils.string.decorate_arguments('name', 'like', 'regex')
    def search(cls, **type):
        '''Search through the names within the database and return the first result matching the keywords specified by `type`.'''
        MANGLED_CODE, MANGLED_DATA, MANGLED_UNKNOWN = getattr(idaapi, 'MANGLED_CODE', 0), getattr(idaapi, 'MANGLED_DATA', 1), getattr(idaapi, 'MANGLED_UNKNOWN', 2)
        Fmangled_type = (lambda ea, string: idaapi.get_mangled_name_type(string)) if hasattr(idaapi, 'get_mangled_name_type') else lambda ea, string: utils.fcompose(utils.frpartial(idaapi.demangle_name, 0), utils.fcondition(operator.truth)(MANGLED_CODE if interface.address.flags(interface.address.within(ea), idaapi.MS_CLS) == idaapi.FF_CODE else MANGLED_DATA, MANGLED_UNKNOWN))(string)
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
    @utils.multicase(ea=internal.types.integer)
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
    @utils.multicase(ea=internal.types.integer)
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
    @utils.multicase(ea=internal.types.integer)
    @classmethod
    def by_bytes(cls, ea, data, **direction):
        """Search through the database at address `ea` for the bytes specified by `data`.

        If `reverse` is specified as a bool, then search backwards from the given address.
        If `radix` is specified, then use it as the numerical radix for describing the bytes.
        If `radix` is not specified, then assume that `data` represents the exact bytes to search.
        """
        radix = direction.get('radix', 0)
        left, right = information.bounds()

        # Figure out the correct format depending on the radix that we were given by the caller.
        formats = {8: "{:0o}".format, 10: "{:d}".format, 16: "{:02X}".format}
        if radix and not operator.contains(formats, radix):
            raise E.InvalidParameterError(u"{:s}.by_bytes({:#x}, {:s}{:s}) : An invalid radix ({:d}) was specified.".format('.'.join([__name__, search.__name__]), ea, '...' if isinstance(data, idaapi.compiled_binpat_vec_t) else utils.string.repr(data), u", {:s}".format(utils.string.kwargs(direction)) if direction else '', radix))
        format = formats[radix or 16]

        # If we're using an earlier version of IDA, then we need to completely build the query ourselves.
        if idaapi.__version__ < 7.5:

            # Convert the bytes directly into a string of base-10 integers.
            if (isinstance(data, internal.types.bytes) and radix == 0) or isinstance(data, internal.types.bytearray):
                query = ' '.join(map(format, bytearray(data)))

            # Convert the string directly into a string of base-10 integers.
            elif isinstance(data, internal.types.string) and radix == 0:
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
        if isinstance(data, (internal.types.bytes, internal.types.bytearray)):
            query = ' '.join(map(format, internal.types.bytearray(data)))

        # If we were given a string, then we need to encode it into some bytes.
        elif isinstance(data, internal.types.string):
            query = ' '.join(map(format, itertools.chain(*(((ord(ch) & 0xff00) // 0x100, (ord(ch) & 0x00ff) // 0x1) for ch in data))))

        # If we were given an idaapi.compiled_binpat_vec_t already, then the user knows what they're doing.
        elif isinstance(data, idaapi.compiled_binpat_vec_t):
            query = data

        else:
            raise E.InvalidParameterError(u"{:s}.by_bytes({:#x}, {:s}{:s}) : A query of an unsupported type ({!s}) was provided.".format('.'.join([__name__, search.__name__]), ea, '...' if isinstance(data, idaapi.compiled_binpat_vec_t) else utils.string.repr(data), u", {:s}".format(utils.string.kwargs(direction)) if direction else '', data.__class__))

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

    @utils.multicase(string=internal.types.string)
    @classmethod
    @utils.string.decorate_arguments('string')
    def by_regex(cls, string, **options):
        '''Search through the database at the current address for the regex matched by `string`.'''
        return cls.by_regex(ui.current.address(), string, **options)
    @utils.multicase(ea=internal.types.integer, string=internal.types.string)
    @classmethod
    @utils.string.decorate_arguments('string')
    def by_regex(cls, ea, string, **options):
        """Search the database at address `ea` for the regex matched by `string`.

        If `reverse` is specified as a bool, then search backwards from the given address.
        If `sensitive` is specified as bool, then perform a case-sensitive search.
        """
        reversed = builtins.next((options[k] for k in ['reverse', 'reversed', 'up', 'backwards'] if k in options), False)
        flags = idaapi.SEARCH_REGEX
        flags |= idaapi.SEARCH_UP if reversed else idaapi.SEARCH_DOWN
        flags |= idaapi.SEARCH_CASE if options.get('sensitive', False) else 0
        res = idaapi.find_text(ea, 0, 0, utils.string.to(string), flags)
        if res == idaapi.BADADDR:
            raise E.SearchResultsError(u"{:s}.by_regex({:#x}, \"{:s}\"{:s}) : The specified regex was not found.".format('.'.join([__name__, cls.__name__]), ea, utils.string.escape(string, '"'), u", {:s}".format(utils.string.kwargs(options)) if options else '', res))
        return res
    byregex = utils.alias(by_regex, 'search')

    @utils.multicase(string=internal.types.string)
    @classmethod
    @utils.string.decorate_arguments('string')
    def by_text(cls, string, **options):
        '''Search through the database at the current address for the text matched by `string`.'''
        return cls.by_text(ui.current.address(), string, **options)
    @utils.multicase(ea=internal.types.integer, string=internal.types.string)
    @classmethod
    @utils.string.decorate_arguments('string')
    def by_text(cls, ea, string, **options):
        """Search the database at address `ea` for the text matched by `string`.

        If `reverse` is specified as a bool, then search backwards from the given address.
        If `sensitive` is specified as bool, then perform a case-sensitive search.
        """
        reversed = builtins.next((options[k] for k in ['reverse', 'reversed', 'up', 'backwards'] if k in options), False)
        flags = 0
        flags |= idaapi.SEARCH_UP if reversed else idaapi.SEARCH_DOWN
        flags |= idaapi.SEARCH_CASE if options.get('sensitive', False) else 0
        res = idaapi.find_text(ea, 0, 0, utils.string.to(string), flags)
        if res == idaapi.BADADDR:
            raise E.SearchResultsError(u"{:s}.by_text({:#x}, \"{:s}\"{:s}) : The specified text was not found.".format('.'.join([__name__, cls.__name__]), ea, utils.string.escape(string, '"'), u", {:s}".format(utils.string.kwargs(options)) if options else '', res))
        return res
    bytext = by_string = bystring = utils.alias(by_text, 'search')

    @utils.multicase(name=internal.types.string)
    @classmethod
    @utils.string.decorate_arguments('name')
    def by_name(cls, name, **options):
        '''Search through the database from the current address for the symbol `name`.'''
        return cls.by_name(ui.current.address(), name, **options)
    @utils.multicase(ea=internal.types.integer, name=internal.types.string)
    @classmethod
    @utils.string.decorate_arguments('name')
    def by_name(cls, ea, name, **options):
        """Search through the database from the address `ea` for the symbol `name`.

        If `reverse` is specified as true, then search backwards from the given address.
        If `ignorecase` is specified as true, then perform a case-insensitive search (slowly).
        """
        reversed = builtins.next((options[k] for k in ['reverse', 'reversed', 'up', 'backwards'] if k in options), False)
        ignore = builtins.next((options[k] for k in ['ignore', 'case', 'ignorecase'] if k in options), False)
        flags = idaapi.SEARCH_IDENT
        flags |= idaapi.SEARCH_UP if reversed else idaapi.SEARCH_DOWN
        flags |= idaapi.SEARCH_CASE if ignore else 0
        res = idaapi.BADADDR if ignore else idaapi.get_name_ea(ea, utils.string.to(name))
        res = idaapi.find_text(ea, 0, 0, utils.string.to(name), flags) if res == idaapi.BADADDR else res
        if res == idaapi.BADADDR:
            raise E.SearchResultsError(u"{:s}.by_name({:#x}, \"{:s}\"{:s}) : The specified name was not found.".format('.'.join([__name__, cls.__name__]), ea, utils.string.escape(name, '"'), u", {:s}".format(utils.string.kwargs(options)) if options else '', res))
        return res
    byname = utils.alias(by_name, 'search')

    @utils.multicase(pattern=(internal.types.string, internal.types.bytes, internal.types.bytearray))
    @classmethod
    def iterate(cls, pattern, **options):
        '''Iterate through all search results that match the `pattern` starting at the current address.'''
        predicate = options.pop('predicate', cls)
        return cls.iterate(ui.current.address(), pattern, predicate, **options)
    @utils.multicase(ea=internal.types.integer, pattern=(internal.types.string, internal.types.bytes, internal.types.bytearray))
    @classmethod
    def iterate(cls, ea, pattern, **options):
        '''Iterate through all search results that match the specified `pattern` starting at address `ea`.'''
        predicate = options.pop('predicate', cls)
        return cls.iterate(ea, pattern, predicate, **options)
    @utils.multicase(pattern=(internal.types.string, internal.types.bytes, internal.types.bytearray))
    @classmethod
    def iterate(cls, pattern, predicate, **options):
        '''Iterate through all search results matched by the function `predicate` with the specified `pattern` starting at the current address.'''
        return cls.iterate(ui.current.address(), pattern, predicate, **options)
    @utils.multicase(ea=internal.types.integer, pattern=(internal.types.string, internal.types.bytes, internal.types.bytearray))
    @classmethod
    def iterate(cls, ea, pattern, predicate, **options):
        '''Iterate through all search results matched by the function `predicate` with the specified `pattern` starting at address `ea`.'''
        reversed = builtins.next((options[k] for k in ['reverse', 'reversed', 'up', 'backwards'] if k in options), False)
        Fnext = address.prev if reversed else address.next

        # If our predicate is a string, then we need to ensure that it's one that
        # we know about. We cheat here by checking it against our current namespace.
        if isinstance(predicate, internal.types.string) and not hasattr(cls, predicate):
            raise E.InvalidParameterError(u"{:s}.iterate({:#x}, {:s}, {:s}, {:s}) : The provided predicate ({:s}) is unknown and does not refer to anything within the \"{:s}\" namespace.".format('.'.join([__name__, cls.__name__]), ea, utils.string.repr(pattern), utils.string.repr(predicate), u", {:s}".format(utils.string.kwargs(options)) if options else '', predicate, cls.__name__))

        # Now we either grab the predicate from the namespace or use it as-is.
        predicate = getattr(cls, predicate) if isinstance(predicate, internal.types.string) else predicate

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
    @utils.multicase(ea=internal.types.integer)
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
        listable = pattern if isinstance(pattern, internal.types.unordered) else [pattern]
        patterns = [pattern for pattern in listable]

        # Extract the radix if we were given one so that we can pretty up the logs.
        radix, formats = direction.get('radix', 16), {8: "{:0o}".format, 10: "{:d}".format, 16: "{:02x}".format}
        if not operator.contains(formats, radix):
            raise E.InvalidParameterError(u"{:s}({:#x}, {:s}{:s}) : An invalid radix ({:d}) was specified.".format('.'.join([__name__, cls.__name__]), ea, utils.string.repr(patterns), u", {:s}".format(utils.string.kwargs(direction)) if direction else '', radix))
        format = formats[radix]

        # Now we need to parse them all individually into an idaapi.compiled_binpat_vec_t().
        result = idaapi.compiled_binpat_vec_t()
        for index, item in enumerate(patterns):

            # If we were given some bytes instead of a string, then format them into a
            # proper string using the specified radix.
            string = ' '.join(map(format, bytearray(item))) if isinstance(item, (internal.types.bytes, internal.types.bytearray)) else item

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

@utils.multicase(ea=internal.types.integer)
def go(ea):
    '''Jump to the specified address at `ea`.'''
    res = ui.current.address()
    if not idaapi.jumpto(interface.address.inside(ea)):
        raise E.DisassemblerError(u"{:s}.go({:#x}) : Unable to jump from the current address ({:#x}) to the specified address ({:#x}).".format(__name__, ea, res, ea))
    return res
@utils.multicase(name=internal.types.string)
@utils.string.decorate_arguments('name', 'suffix')
def go(name, *suffix):
    '''Jump to the address of the symbol with the specified `name`.'''
    res = (name,) + suffix
    string = interface.tuplename(*res)
    ea = idaapi.get_name_ea(idaapi.BADADDR, utils.string.to(string))
    if ea == idaapi.BADADDR:
        raise E.AddressNotFoundError(u"{:s}.go({!r}) : Unable to find the address for the specified symbol \"{:s}\".".format(__name__, ea, res if suffix else string, utils.string.escape(string, '"')))
    return go(ea)
jump = jump_to = jumpto = utils.alias(go)

def go_offset(offset):
    '''Jump to the specified `offset` within the database.'''
    current, target = ui.current.address(), address.by_offset(offset)
    res = address.offset(current)
    if not idaapi.jumpto(interface.address.inside(target)):
        raise E.DisassemblerError(u"{:s}.go_offset({:#x}) : Unable to jump from the current offset ({:+#x}) at {:#x} to the specified offset ({:+#x}) at {:#x}.".format(__name__, offset, res, current, offset, target))
    return res
goof = gooffset = gotooffset = goto_offset = utils.alias(go_offset)

@utils.multicase()
def name(**flags):
    '''Return the name at the current address.'''
    return name(ui.current.address(), **flags)
@utils.multicase(ea=internal.types.integer)
def name(ea, **flags):
    """Return the name defined at the address specified by `ea`.

    If `flags` is specified, then use the specified value as the flags.
    """
    ea = interface.address.inside(ea)
    return interface.name.get(ea, flags['flags']) if 'flags' in flags else interface.name.get(ea)
@utils.multicase(string=internal.types.string)
@utils.string.decorate_arguments('string', 'suffix')
def name(string, *suffix, **flags):
    '''Renames the current address to `string`.'''
    return name(ui.current.address(), string, *suffix, **flags)
@utils.multicase(none=internal.types.none)
def name(none, **flags):
    '''Removes the name at the current address.'''
    return name(ui.current.address(), none or '', **flags)
@utils.multicase(ea=internal.types.integer, fullname=internal.types.tuple)
def name(ea, fullname, **flags):
    '''Renames the address specifed by `ea` to the given packed `fullname`.'''
    return name(ea, *fullname, **flags)
@utils.multicase(ea=internal.types.integer, string=internal.types.string)
@utils.string.decorate_arguments('string', 'suffix')
def name(ea, string, *suffix, **flags):
    """Renames the address specified by `ea` to `string`.

    If `ea` is pointing to a global and is not contained by a function, then by default the label will be added to the Names list.
    If `flags` is specified, then use the specified value as the flags.
    If the boolean `listed` is specified, then specify whether to add the label to the Names list or not.
    """
    ea = interface.address.inside(ea)

    # combine name with its suffix
    res = (string,) + suffix
    string = interface.tuplename(*res)

    # if the bool `listed` is True, then ensure that it's added to the name list.
    #if 'listed' in flags:
    #    return interface.name.set(ea, string, 0 if flags.get('listed', False) else idaapi.SN_NOLIST, idaapi.SN_NOLIST)

    # if custom flags were specified, then just use those as they should get priority.
    if 'flags' in flags:
        maximum = max(idaapi.SN_LOCAL, flags['flags'])
        return interface.name.set(ea, string, flags['flags'], 2 * pow(2, int(math.log(maximum, 2))) - 1)

    # otherwise, we need to check for "listed", "weak", and "public".
    flag, preserve = 0 if flags.get('listed', False) else idaapi.SN_NOLIST, idaapi.SN_NOLIST if 'listed' in flags else 0
    if 'weak' in flags:
        flag, preserve = flag | (idaapi.SN_WEAK if flags.get('weak', False) else idaapi.SN_NON_WEAK), preserve | idaapi.SN_WEAK | idaapi.SN_NON_WEAK
    elif 'public' in flags:
        flag, preserve = flag | (idaapi.SN_PUBLIC if flags.get('public', False) else idaapi.SN_NON_PUBLIC), preserve | idaapi.SN_PUBLIC | idaapi.SN_NON_PUBLIC
    return interface.name.set(ea, string, flag, preserve) if 'listed' in flags else interface.name.set(ea, string, flag)

@utils.multicase(ea=internal.types.integer, none=internal.types.none)
def name(ea, none, **flags):
    '''Removes the name defined at the address `ea`.'''
    return name(ea, none or '', **flags)

@utils.multicase()
def mangled():
    '''Return the mangled name at the current address.'''
    return mangled(ui.current.address())
@utils.multicase(ea=internal.types.integer)
def mangled(ea):
    '''Return the mangled name at the address specified by `ea`.'''
    MANGLED_CODE, MANGLED_DATA, MANGLED_UNKNOWN = getattr(idaapi, 'MANGLED_CODE', 0), getattr(idaapi, 'MANGLED_DATA', 1), getattr(idaapi, 'MANGLED_UNKNOWN', 2)
    Fmangled_type = idaapi.get_mangled_name_type if hasattr(idaapi, 'get_mangled_name_type') else utils.fcompose(utils.frpartial(idaapi.demangle_name, 0), utils.fcondition(operator.truth)(MANGLED_CODE if type.code(ea) else MANGLED_DATA, MANGLED_UNKNOWN))

    result = interface.name.get(ea)
    mangled_name_type_t = Fmangled_type(utils.string.to(result))
    if mangled_name_type_t == MANGLED_UNKNOWN:
        logging.warning(u"{:s}.mangled({:#x}) : The name at the given address ({:#x}) was not mangled ({:d}) and will be the same as returning the {:s} name.".format(__name__, ea, ea, mangled_name_type_t, 'regular'))
    return result
@utils.multicase(string=internal.types.string)
@utils.string.decorate_arguments('string','suffix')
def mangled(string, *suffix):
    '''Rename the current address to the mangled version of `string` and return its previous mangled value.'''
    return mangled(ui.current.address(), string, *suffix)
@utils.multicase(none=internal.types.none)
def mangled(none):
    '''Remove the mangled name at the current address and return its previous mangled value.'''
    return mangled(ui.current.address(), none)
@utils.multicase(ea=internal.types.integer, string=internal.types.string)
@utils.string.decorate_arguments('string', 'suffix')
def mangled(ea, string, *suffix):
    '''Rename the address specified by `ea` to the mangled version of `string` and return its previous mangled value.'''
    MANGLED_CODE, MANGLED_DATA, MANGLED_UNKNOWN = getattr(idaapi, 'MANGLED_CODE', 0), getattr(idaapi, 'MANGLED_DATA', 1), getattr(idaapi, 'MANGLED_UNKNOWN', 2)
    Fmangled_type = idaapi.get_mangled_name_type if hasattr(idaapi, 'get_mangled_name_type') else utils.fcompose(utils.frpartial(idaapi.demangle_name, 0), utils.fcondition(operator.truth)(MANGLED_CODE if type.code(ea) else MANGLED_DATA, MANGLED_UNKNOWN))

    mangled_name_type_t = Fmangled_type(utils.string.to(string))
    if mangled_name_type_t == MANGLED_UNKNOWN:
        raise NotImplementedError(u"{:s}.mangled({:#x}, {:s}) : Unable to mangle the specified name (\"{:s}\") before applying it to the address ({:#x}).".format(__name__, ea, ', '.join(map("{!r}".format, itertools.chain([string], suffix))), utils.string.escape(string, '"'), ea))
    if suffix:
        raise NotImplementedError(u"{:s}.mangled({:#x}, {:s}) : Unable to attach the suffix (\"{:s}\") to the unmangled name (\"{:s}\") before applying it to the address ({:#x}).".format(__name__, ea, ', '.join(map("{!r}".format, itertools.chain([string], suffix))), interface.tuplename(*suffix), internal.declaration.demangle(string), ea))
    # FIXME: mangle the string that we were given according to the schema for
    #        the default compiler type with the suffix appended to its name.
    logging.warning(u"{:s}.mangled({:#x}, {:s}) : The specified name (\"{:s}\") is already mangled ({:d}) and will be assigned to the given address ({:#x}) as \"{:s}\".".format(__name__, ea, ', '.join(map("{!r}".format, itertools.chain([string], suffix))), utils.string.escape(string, '"'), mangled_name_type_t, ea, internal.declaration.demangle(string)))
    return interface.name.set(ea, interface.tuplename(*itertools.chain([string], suffix)))
@utils.multicase(ea=internal.types.integer, none=internal.types.none)
def mangled(ea, none):
    '''Remove the name at the address specified by `ea` and return its previous mangled value.'''
    MANGLED_CODE, MANGLED_DATA, MANGLED_UNKNOWN = getattr(idaapi, 'MANGLED_CODE', 0), getattr(idaapi, 'MANGLED_DATA', 1), getattr(idaapi, 'MANGLED_UNKNOWN', 2)
    Fmangled_type = idaapi.get_mangled_name_type if hasattr(idaapi, 'get_mangled_name_type') else utils.fcompose(utils.frpartial(idaapi.demangle_name, 0), utils.fcondition(operator.truth)(MANGLED_CODE if type.code(ea) else MANGLED_DATA, MANGLED_UNKNOWN))
    GN_DEMANGLED = getattr(idaapi, 'GN_DEMANGLED', 0)

    flags = functools.reduce(operator.or_, [GN_DEMANGLED, idaapi.GN_SHORT])
    string, _ = interface.name.get(ea, flags), interface.name.set(ea, none)
    mangled_name_type_t = Fmangled_type(utils.string.to(string))
    if mangled_name_type_t == MANGLED_UNKNOWN:
        logging.warning(u"{:s}.mangled({:#x}, {!s}) : The name at the given address ({:#x}) was not mangled ({:d}) and will be the same as returning the {:s} name.".format(__name__, ea, none, ea, mangled_name_type_t, 'regular'))
    return string
mangle = utils.alias(mangled)

@utils.multicase()
def unmangled():
    '''Return the name at the current address in its unmangled form.'''
    return unmangled(ui.current.address())
@utils.multicase(ea=internal.types.integer)
def unmangled(ea):
    '''Return the name at the address specified by `ea` in its unmangled form.'''
    GN_DEMANGLED = getattr(idaapi, 'GN_DEMANGLED', 0)

    flags = functools.reduce(operator.or_, [GN_DEMANGLED, idaapi.GN_SHORT])
    result = interface.name.get(ea, flags)
    return result if hasattr(idaapi, 'GN_DEMANGLED') else internal.declaration.demangle(result)
@utils.multicase(string=internal.types.string)
@utils.string.decorate_arguments('string','suffix')
def unmangled(string, *suffix):
    '''Rename the current address using the mangled version of `string` and return its previous unmangled value.'''
    return unmangled(ui.current.address(), string, *suffix)
@utils.multicase(none=internal.types.none)
def unmangled(none):
    '''Remove the name at the current address and return its previous unmangled value.'''
    return unmangled(ui.current.address(), none)
@utils.multicase(ea=internal.types.integer, string=internal.types.string)
@utils.string.decorate_arguments('string', 'suffix')
def unmangled(ea, string, *suffix):
    '''Rename the address specified by `ea` using the mangled version of `string` and return its previous unmangled value.'''
    MANGLED_CODE, MANGLED_DATA, MANGLED_UNKNOWN = getattr(idaapi, 'MANGLED_CODE', 0), getattr(idaapi, 'MANGLED_DATA', 1), getattr(idaapi, 'MANGLED_UNKNOWN', 2)
    Fmangled_type = idaapi.get_mangled_name_type if hasattr(idaapi, 'get_mangled_name_type') else utils.fcompose(utils.frpartial(idaapi.demangle_name, 0), utils.fcondition(operator.truth)(MANGLED_CODE if type.code(ea) else MANGLED_DATA, MANGLED_UNKNOWN))
    GN_DEMANGLED = getattr(idaapi, 'GN_DEMANGLED', 0)

    mangled_name_type_t = Fmangled_type(utils.string.to(string))
    if mangled_name_type_t != MANGLED_UNKNOWN:
        logging.warning(u"{:s}.unmangled({:#x}, {:s}) : The specified name (\"{:s}\") is already mangled ({:d}) and will be assigned to the given address ({:#x}) as \"{:s}\".".format(__name__, ea, ', '.join(map("{!r}".format, itertools.chain([string], suffix))), utils.string.escape(string, '"'), mangled_name_type_t, ea, internal.declaration.demangle(string)))
    if suffix:
        raise NotImplementedError(u"{:s}.unmangled({:#x}, {:s}) : Unable to attach the suffix (\"{:s}\") to the unmangled name (\"{:s}\") before applying it to the address ({:#x}).".format(__name__, ea, ', '.join(map("{!r}".format, itertools.chain([string], suffix))), interface.tuplename(*suffix), internal.declaration.demangle(string), ea))
    # FIXME: correct the string, doing whatever it takes to keep it the same
    #        when it gets mangled(?) and append the given suffix to its name.
    flags = functools.reduce(operator.or_, [GN_DEMANGLED, idaapi.GN_SHORT])
    result, original = interface.name.get(ea, flags), interface.name.set(ea, interface.tuplename(*itertools.chain([string], suffix)), 0, idaapi.SN_LOCAL)
    return result if hasattr(idaapi, 'GN_DEMANGLED') else internal.declaration.demangle(result)
@utils.multicase(ea=internal.types.integer, none=internal.types.none)
def unmangled(ea, none):
    '''Remove the name at the address specified by `ea` and return its previous unmangled value.'''
    MANGLED_CODE, MANGLED_DATA, MANGLED_UNKNOWN = getattr(idaapi, 'MANGLED_CODE', 0), getattr(idaapi, 'MANGLED_DATA', 1), getattr(idaapi, 'MANGLED_UNKNOWN', 2)
    Fmangled_type = idaapi.get_mangled_name_type if hasattr(idaapi, 'get_mangled_name_type') else utils.fcompose(utils.frpartial(idaapi.demangle_name, 0), utils.fcondition(operator.truth)(MANGLED_CODE if type.code(ea) else MANGLED_DATA, MANGLED_UNKNOWN))
    GN_DEMANGLED = getattr(idaapi, 'GN_DEMANGLED', 0)

    flags = functools.reduce(operator.or_, [GN_DEMANGLED, idaapi.GN_SHORT])
    string, result = interface.name.get(ea, flags), interface.name.set(ea, none, 0, idaapi.SN_LOCAL)
    mangled_name_type_t = Fmangled_type(utils.string.to(string))
    if mangled_name_type_t == MANGLED_UNKNOWN:
        logging.warning(u"{:s}.unmangled({:#x}, {!s}) : The name at the given address ({:#x}) was not mangled ({:d}) and will be the same as returning the {:s} name.".format(__name__, ea, none, ea, mangled_name_type_t, 'regular'))
    return result if hasattr(idaapi, 'GN_DEMANGLED') else internal.declaration.demangle(result)
unmangle = demangle = demangled = utils.alias(unmangled)

@utils.multicase()
def color():
    '''Return the color (RGB) for the item at the current address.'''
    return color(ui.current.address())
@utils.multicase(none=internal.types.none)
def color(none):
    '''Remove the color from the item at the current address.'''
    DEFCOLOR = 0xffffffff
    res = interface.address.color(ui.current.address(), DEFCOLOR)
    return None if res == DEFCOLOR else res
@utils.multicase(ea=internal.types.integer)
def color(ea):
    '''Return the color (RGB) for the item at the address specified by `ea`.'''
    DEFCOLOR = 0xffffffff
    res = interface.address.color(interface.address.inside(ea))
    return None if res == DEFCOLOR else res
@utils.multicase(ea=internal.types.integer, none=internal.types.none)
def color(ea, none):
    '''Remove the color from the item at the address specified by `ea`.'''
    DEFCOLOR = 0xffffffff
    res = interface.address.color(interface.address.inside(ea), DEFCOLOR)
    return None if res == DEFCOLOR else res
@utils.multicase(ea=internal.types.integer, rgb=internal.types.integer)
def color(ea, rgb):
    '''Set the color for the item at address `ea` to `rgb`.'''
    DEFCOLOR = 0xffffffff
    res = interface.address.color(interface.address.inside(ea), rgb)
    return None if res == DEFCOLOR else res

@utils.multicase()
def comment(**repeatable):
    '''Return the comment at the current address.'''
    return comment(ui.current.address(), **repeatable)
@utils.multicase(ea=internal.types.integer)
def comment(ea, **repeatable):
    """Return the comment at the address `ea`.

    If the bool `repeatable` is specified, then return the repeatable comment.
    """
    res = idaapi.get_cmt(interface.address.inside(ea), repeatable.get('repeatable', False))

    # return the string in a format the user can process
    return utils.string.of(res)
@utils.multicase(string=internal.types.string)
@utils.string.decorate_arguments('string')
def comment(string, **repeatable):
    '''Set the comment at the current address to `string`.'''
    return comment(ui.current.address(), string, **repeatable)
@utils.multicase(none=internal.types.none)
def comment(none, **repeatable):
    '''Remove the comment at the current address.'''
    return comment(ui.current.address(), none or '', **repeatable)
@utils.multicase(ea=internal.types.integer, string=internal.types.string)
@utils.string.decorate_arguments('string')
def comment(ea, string, **repeatable):
    """Set the comment at the address `ea` to `string`.

    If the bool `repeatable` is specified, then modify the repeatable comment.
    """
    # apply the comment to the specified address
    res, ok = comment(ea, **repeatable), idaapi.set_cmt(interface.address.inside(ea), utils.string.to(string), repeatable.get('repeatable', False))
    if not ok:
        raise E.DisassemblerError(u"{:s}.comment({:#x}, {!r}{:s}) : Unable to call `{:s}({:#x}, \"{:s}\", {!s})`.".format(__name__, ea, string, u", {:s}".format(utils.string.kwargs(repeatable)) if repeatable else '', utils.pycompat.fullname(idaapi.set_cmt), ea, utils.string.escape(string, '"'), repeatable.get('repeatable', False)))
    return res
@utils.multicase(ea=internal.types.integer, none=internal.types.none)
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

        `address` or `ea` - Filter the entrypoints by an address or a list of addresses
        `name` - Filter the entrypoints by a name or a list of names
        `like` - Filter the entrypoint names according to a glob
        `bounds` - Filter the entrypoints within the given boundaries
        `regex` - Filter the entrypoint names according to a regular-expression
        `index` - Filter the entrypoints by an index or a list of indices
        `ordinal` - Filter the entrypoint by an ordinal or a list of ordinals
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
    __matcher__.combinator('address', utils.fcondition(utils.finstance(internal.types.integer))(utils.fpartial(utils.fpartial, operator.eq), utils.fpartial(utils.fpartial, operator.contains)), idaapi.get_entry_ordinal, idaapi.get_entry)
    __matcher__.alias('ea', 'address')
    __matcher__.boolean('ge', operator.le, idaapi.get_entry_ordinal, idaapi.get_entry), __matcher__.alias('greater', 'ge')
    __matcher__.boolean('gt', operator.lt, idaapi.get_entry_ordinal, idaapi.get_entry)
    __matcher__.boolean('le', operator.ge, idaapi.get_entry_ordinal, idaapi.get_entry), __matcher__.alias('less', 'le')
    __matcher__.boolean('lt', operator.gt, idaapi.get_entry_ordinal, idaapi.get_entry)
    __matcher__.combinator('name', utils.fcondition(utils.finstance(internal.types.string))(utils.fcompose(operator.methodcaller('lower'), utils.fpartial(utils.fpartial, operator.eq)), utils.fcompose(utils.fpartial(map, operator.methodcaller('lower')), internal.types.set, utils.fpartial(utils.fpartial, operator.contains))), idaapi.get_entry_ordinal, utils.fmap(idaapi.get_entry_name, utils.fcompose(idaapi.get_entry, utils.fcondition(interface.function.has)(function.name, unmangled))), utils.fpartial(filter, None), utils.itake(1), operator.itemgetter(0), utils.fdefault(''), utils.string.of)
    __matcher__.combinator('like', utils.fcompose(fnmatch.translate, utils.fpartial(re.compile, flags=re.IGNORECASE), operator.attrgetter('match')), idaapi.get_entry_ordinal, utils.fmap(idaapi.get_entry_name, utils.fcompose(idaapi.get_entry, utils.fcondition(interface.function.has)(function.name, unmangled))), utils.fpartial(filter, None), utils.itake(1), operator.itemgetter(0), utils.fdefault(''), utils.string.of)
    __matcher__.combinator('regex', utils.fcompose(utils.fpartial(re.compile, flags=re.IGNORECASE), operator.attrgetter('match')), idaapi.get_entry_ordinal, utils.fmap(idaapi.get_entry_name, utils.fcompose(idaapi.get_entry, utils.fcondition(interface.function.has)(function.name, unmangled))), utils.fpartial(filter, None), utils.itake(1), operator.itemgetter(0), utils.fdefault(''), utils.string.of)
    __matcher__.mapping('function', interface.function.has, idaapi.get_entry_ordinal, idaapi.get_entry)
    __matcher__.mapping('typed', operator.truth, idaapi.get_entry_ordinal, idaapi.get_entry, lambda ea: idaapi.get_tinfo2(ea, idaapi.tinfo_t()) if idaapi.__version__ < 7.0 else idaapi.get_tinfo(idaapi.tinfo_t(), ea))
    __matcher__.boolean('tagged', lambda parameter, keys: operator.truth(keys) == parameter if isinstance(parameter, internal.types.bool) else operator.contains(keys, parameter) if isinstance(parameter, internal.types.string) else keys & internal.types.set(parameter), idaapi.get_entry_ordinal, idaapi.get_entry, lambda ea: internal.tags.function.get(ea) if interface.function.has(ea) else internal.tags.address.get(ea), operator.methodcaller('keys'), internal.types.set)
    __matcher__.combinator('ordinal', utils.fcondition(utils.finstance(internal.types.integer))(utils.fpartial(utils.fpartial, operator.eq), utils.fpartial(utils.fpartial, operator.contains)), idaapi.get_entry_ordinal)
    __matcher__.combinator('index', utils.fcondition(utils.finstance(internal.types.integer))(utils.fpartial(utils.fpartial, operator.eq), utils.fpartial(utils.fpartial, operator.contains)))
    __matcher__.combinator('bounds', utils.fcondition(utils.finstance(interface.bounds_t))(operator.attrgetter('contains'), utils.fcompose(utils.funpack(interface.bounds_t), operator.attrgetter('contains'))), idaapi.get_entry_ordinal, idaapi.get_entry)
    __matcher__.predicate('predicate', idaapi.get_entry_ordinal), __matcher__.alias('pred', 'predicate')

    def __new__(cls, *string, **type):
        '''Return the address of each entry point defined within the database as a list.'''
        return [ea for ea in cls.iterate(*string, **type)]

    @utils.multicase(string=internal.types.string)
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

    @utils.multicase()
    @classmethod
    def at(cls):
        '''Return the address of the entry point at the current address.'''
        return cls.at(ui.current.address())
    @utils.multicase(ea=internal.types.integer)
    @classmethod
    def at(cls, ea):
        '''Return the address of the entry point at the address specified by `ea`.'''
        if not interface.function.has(ea):
            address = interface.address.inside(ea)

        # If we're within a function then adjust our address to its entrypoint.
        else:
            fn = idaapi.get_func(ea)
            address, _ = interface.range.bounds(fn)

        # Now we should be able to get its index and use it to return the address.
        res = cls.__index__(address)
        if res is None:
            raise E.MissingTypeOrAttribute(u"{:s}.at({:#x}) : No entry point was found at the specified address ({:#x}).".format('.'.join([__name__, cls.__name__]), ea, address))
        return cls.__address__(res)

    @utils.multicase()
    @classmethod
    @utils.string.decorate_arguments('name')
    def has(cls, **type):
        '''Return whether the current address is referencing an entry point.'''
        if 'ordinal' in type:
            ea = idaapi.get_entry(type['ordinal'])
            return ea != idaapi.BADADDR
        elif 'index' in type:
            return cls.__entryordinal__(type['index']) > 0
        elif type:
            raise E.InvalidParameterError(u"{:s}.has({:s}) : The given keyword parameter{:s} not supported.".format('.'.join([__name__, cls.__name__]), utils.string.kwargs(type), ' is' if len(type) == 1 else 's are'))
        return cls.has(ui.current.address())
    @utils.multicase(ea=internal.types.integer)
    @classmethod
    def has(cls, ea):
        '''Return whether the address in `ea` is referencing an entry point.'''
        if not interface.function.has(ea):
            address = interface.address.inside(ea)

        # If the address is a function, then translate it to the function address.
        else:
            fn = idaapi.get_func(ea)
            address, _ = interface.range.bounds(fn)

        # Now we'll just try to gets its index, and if we got one then it's an export.
        res = cls.__index__(address)
        return res is not None

    @utils.multicase(ordinal=internal.types.integer)
    @classmethod
    def by(cls, ordinal):
        '''Return the address of the entry point at the given `ordinal`.'''
        ea = idaapi.get_entry(ordinal)
        if ea == idaapi.BADADDR:
            raise E.ItemNotFoundError(u"{:s}.by_ordinal({:d}) : No entry point was found with the specified ordinal ({:d}).".format('.'.join([__name__, cls.__name__]), ordinal, ordinal))
        return ea
    @utils.multicase()
    @classmethod
    @utils.string.decorate_arguments('name', 'like', 'regex')
    def by(cls, **type):
        '''Return the address of the first entry point that matches the keywords specified by `type`.'''
        return cls.search(**type)

    @utils.multicase(name=internal.types.string)
    @classmethod
    @utils.string.decorate_arguments('name')
    def iterate(cls, name):
        '''Iterate through the entry points from the database that match the glob specified by `name`.'''
        return cls.iterate(like=name)
    @utils.multicase(bounds=interface.bounds_t)
    @classmethod
    def iterate(cls, bounds):
        '''Iterate through the entry points from the database within the given `bounds`.'''
        return cls.iterate(predicate=operator.truth, bounds=bounds)
    @utils.multicase()
    @classmethod
    @utils.string.decorate_arguments('name', 'like', 'regex')
    def iterate(cls, **type):
        '''Iterate through the entry points from the database that match the keywords specified by `type`.'''
        for ea in cls.__iterate__(**type):
            yield cls.__address__(ea)
        return

    @classmethod
    def __index__(cls, ea):
        '''Return the index of the entry point at the specified `address`.'''
        f = utils.fcompose(idaapi.get_entry_ordinal, idaapi.get_entry)

        # Iterate through each entry point, and yield a tuple containing its address and index.
        Ftransform = utils.fcompose(utils.fmap(f, utils.fidentity), tuple)
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
    __entryname__ = staticmethod(utils.fcompose(idaapi.get_entry_ordinal, utils.fmap(idaapi.get_entry_name, utils.fcompose(idaapi.get_entry, utils.fcondition(interface.function.has)(function.name, unmangled))), utils.fpartial(filter, None), utils.itake(1), operator.itemgetter(0), utils.fdefault(''), utils.string.of))
    # Return the ordinal of the entry point at the specified `index`.
    __entryordinal__ = staticmethod(idaapi.get_entry_ordinal)

    @utils.multicase()
    @classmethod
    def ordinal(cls):
        '''Return the ordinal of the entry point at the current address.'''
        return cls.ordinal(ui.current.address())
    @utils.multicase(ea=internal.types.integer)
    @classmethod
    def ordinal(cls, ea):
        '''Return the ordinal of the entry point at the address `ea`.'''
        if not interface.function.has(ea):
            address = interface.address.inside(ea)

        # If we're within a function then adjust our address to its entrypoint.
        else:
            fn = idaapi.get_func(ea)
            address, _ = interface.range.bounds(fn)

        # Now we can use our determined address to get the index and then its ordinal.
        res = cls.__index__(address)
        if res is None:
            raise E.MissingTypeOrAttribute(u"{:s}.ordinal({:#x}) : No entry point was found at the specified address ({:#x}).".format('.'.join([__name__, cls.__name__]), ea, address))
        return cls.__entryordinal__(res)

    @utils.multicase()
    @classmethod
    def name(cls):
        '''Return the name of the entry point at the current address.'''
        return cls.name(ui.current.address())
    @utils.multicase(ea=internal.types.integer)
    @classmethod
    def name(cls, ea):
        '''Return the name of the entry point at the address `ea`.'''
        if not interface.function.has(ea):
            address = interface.address.inside(ea)

        # If we're within a function then adjust our address to its entrypoint.
        else:
            fn = idaapi.get_func(ea)
            address, _ = interface.range.bounds(fn)

        # Now we can use the address to determine the index and then return its name.
        res = cls.__index__(address)
        if res is None:
            raise E.MissingTypeOrAttribute(u"{:s}.name({:#x}) : No entry point was found at the specified address ({:#x}).".format('.'.join([__name__, cls.__name__]), ea, address))
        return cls.__entryname__(res)

    @utils.multicase(name=internal.types.string)
    @classmethod
    @utils.string.decorate_arguments('name')
    def list(cls, name):
        '''List the entry points from the database that match the glob `name`.'''
        return cls.list(like=name)
    @utils.multicase(bounds=interface.bounds_t)
    @classmethod
    def list(cls, bounds):
        '''List the entry points from the database within the given `bounds`.'''
        return cls.list(like=name)
    @utils.multicase()
    @classmethod
    @utils.string.decorate_arguments('name', 'like', 'regex')
    def list(cls, **type):
        '''List the entry points from the database that match the keywords specified by `type`.'''
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
            tags = internal.tags.function.get(ea) if interface.function.has(ea) else internal.tags.address.get(ea)
            realname = cls.__entryname__(index) or interface.name.get(ea)

            # Some flags that could be useful.
            fclass = 'A' if t.data(ea) or t.unknown(ea) else 'D' if interface.function.has(ea) and function.type.decompiled(ea) else 'F' if interface.function.has(ea) else 'C' if t.code(ea) else '-'
            finitialized = '-' if not t.initialized(ea) else 'C' if t.code(ea) else 'D' if t.data(ea) else '^'
            ftyped = 'T' if get_tinfo(idaapi.tinfo_t(), ea) else 't' if t.has(ea) else '-'
            tags.pop('__name__', None)
            ftagged = '-' if not tags else '*' if any(not item.startswith('__') for item in tags) else '+'
            flags = itertools.chain(fclass, finitialized, ftyped, ftagged)

            # If we're within a function, then display the type information if available
            # while being aware of name mangling. If there's no type information, then
            # use the unmangled name for displaying the export.
            if interface.function.has(ea):
                ti, mangled_name_type_t = idaapi.tinfo_t(), Fmangled_type(utils.string.to(realname))
                dname = realname if mangled_name_type_t == MANGLED_UNKNOWN else utils.string.of(idaapi.demangle_name(utils.string.to(realname), MNG_NODEFINIT|MNG_NOPTRTYP) or realname)
                demangled = utils.string.of(idaapi.demangle_name(utils.string.to(realname), MNG_LONG_FORM|MNG_NOSCTYP|MNG_NOCALLC)) or realname
                description = idaapi.print_tinfo('', 0, 0, idaapi.PRTYPE_DEF, ti, utils.string.to(dname), '') if get_tinfo(ti, ea) else demangled

            # Otherwise, we always try to display the type regardless of what's available.
            else:
                description = tags.get('__typeinfo__', realname)
            six.print_(u"{:<{:d}s} {:s} {:<#{:d}x} : {:s} : {:s}".format("[{:d}]".format(index), 2 + math.trunc(cindex), "{:>{:d}s}".format('' if ea == ordinal else "(#{:d})".format(ordinal), 2 + 1 + math.trunc(cindex)), ea, 2 + math.trunc(caddr), ''.join(flags), description))
        return

    @utils.multicase(name=internal.types.string)
    @classmethod
    @utils.string.decorate_arguments('name')
    def search(cls, name):
        '''Search through the entry points within the database that match the glob `name` and return the first result.'''
        return cls.search(like=name)
    @utils.multicase()
    @classmethod
    @utils.string.decorate_arguments('name', 'like', 'regex')
    def search(cls, **type):
        '''Search through the entry points within the database and return the first result matching the keywords specified by `type`.'''
        query_s = utils.string.kwargs(type)

        listable = [item for item in cls.__iterate__(**type)]
        if len(listable) > 1:
            messages = ((u"[{:d}] ({:s}) {:#x} : {:s} {:s}".format(idx, '' if ordinal == ea else "#{:d}".format(ordinal), ea, '[FUNC]' if interface.function.has(ea) else '[ADDR]', name or unmangled(ea))) for idx, ordinal, name, ea in map(utils.fmap(utils.fidentity, cls.__entryordinal__, cls.__entryname__, cls.__address__), listable))
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
        ea, entryname, ordinal = ui.current.address(), interface.name.get(ui.current.address()) or interface.function.name(ui.current.address()), idaapi.get_entry_qty()
        if entryname is None:
            raise E.MissingTypeOrAttribute(u"{:s}.new({:#x}) : Unable to determine name at address.".format( '.'.join([__name__, cls.__name__]), ea))
        return cls.new(ea, entryname, ordinal)
    @utils.multicase(ea=internal.types.integer)
    @classmethod
    def new(cls, ea):
        '''Makes an entry point at the specified address `ea`.'''
        entryname, ordinal = interface.name.get(ea) or interface.function.name(ea), idaapi.get_entry_qty()
        if entryname is None:
            raise E.MissingTypeOrAttribute(u"{:s}.new({:#x}) : Unable to determine name at address.".format( '.'.join([__name__, cls.__name__]), ea))
        return cls.new(ea, entryname, ordinal)
    @utils.multicase(name=internal.types.string)
    @classmethod
    @utils.string.decorate_arguments('name')
    def new(cls, name):
        '''Adds the current address as an entry point using `name` and the next available index as the ordinal.'''
        return cls.new(ui.current.address(), name, idaapi.get_entry_qty())
    @utils.multicase(ea=internal.types.integer, name=internal.types.string)
    @classmethod
    @utils.string.decorate_arguments('name')
    def new(cls, ea, name):
        '''Makes the specified address `ea` an entry point having the specified `name`.'''
        ordinal = idaapi.get_entry_qty()
        return cls.new(ea, name, ordinal)
    @utils.multicase(name=internal.types.string, ordinal=internal.types.integer)
    @classmethod
    @utils.string.decorate_arguments('name')
    def new(cls, name, ordinal):
        '''Adds an entry point with the specified `name` to the database using `ordinal` as its index.'''
        return cls.new(ui.current.address(), name, ordinal)
    @utils.multicase(ea=internal.types.integer, name=internal.types.string, ordinal=internal.types.integer)
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
    return internal.tags.address.get(ui.current.address())
@utils.multicase(ea=internal.types.integer)
def tag(ea):
    '''Return all of the tags defined at address `ea`.'''
    return internal.tags.address.get(ea)
@utils.multicase(key=internal.types.string)
@utils.string.decorate_arguments('key')
def tag(key):
    '''Return the tag identified by `key` at the current address.'''
    return tag(ui.current.address(), key)
@utils.multicase(key=internal.types.string)
@utils.string.decorate_arguments('key', 'value')
def tag(key, value):
    '''Set the tag identified by `key` to `value` at the current address.'''
    return internal.tags.address.set(ui.current.address(), key, value)
@utils.multicase(ea=internal.types.integer, key=internal.types.string)
@utils.string.decorate_arguments('key')
def tag(ea, key):
    '''Return the tag identified by `key` from the address `ea`.'''
    res = internal.tags.address.get(ea)
    if key in res:
        return res[key]
    raise E.MissingTagError(u"{:s}.tag({:#x}, {!r}) : Unable to read tag (\"{:s}\") from address.".format(__name__, ea, key, utils.string.escape(key, '"')))
@utils.multicase(ea=internal.types.integer, key=internal.types.string)
@utils.string.decorate_arguments('key', 'value')
def tag(ea, key, value):
    '''Set the tag identified by `key` to `value` at the address `ea`.'''
    ea = interface.address.inside(ea)
    return internal.tags.address.set(ea, key, value)
@utils.multicase(key=internal.types.string, none=internal.types.none)
def tag(key, none):
    '''Remove the tag identified by `key` from the current address.'''
    return internal.tags.address.remove(ui.current.address(), key, none)
@utils.multicase(ea=internal.types.integer, key=internal.types.string, none=internal.types.none)
@utils.string.decorate_arguments('key')
def tag(ea, key, none):
    '''Removes the tag identified by `key` at the address `ea`.'''
    ea = interface.address.inside(ea)
    return internal.tags.address.remove(ea, key, none)

@utils.multicase(tag=internal.types.string)
@utils.string.decorate_arguments('tag', 'And', 'Or', 'require', 'requires', 'required', 'include', 'includes', 'included')
def select(tag, *required, **boolean):
    '''Query the globals in the database for the given `tag` and any others that may be `required`.'''
    res = {tag} | {item for item in required}
    boolean['required'] = {item for item in boolean.get('required', [])} | res
    return select(**boolean)
@utils.multicase()
@utils.string.decorate_arguments('And', 'Or', 'require', 'requires', 'required', 'include', 'includes', 'included')
def select(**boolean):
    """Query the globals in the database for the tags specified by `boolean` and yield a tuple for each matching address with selected tags and values.

    If `require` is given as an iterable of tag names then require that each returned address uses them.
    If `include` is given as an iterable of tag names then include the tags for each returned address if available.
    """
    boolean = {key : {item for item in value} if isinstance(value, internal.types.unordered) else {value} for key, value in boolean.items()}

    # Nothing specific was queried, so just yield all tags that are available.
    if not boolean:
        for ea in internal.comment.globals.address():
            ui.navigation.set(ea)
            Ftag, owners = (internal.tags.function.get, {f for f in interface.function.owners(ea)}) if interface.function.has(ea) else (internal.tags.address.get, {ea})
            tags = Ftag(ea)
            if tags and ea in owners: yield ea, tags
            elif ea not in owners: logging.info(u"{:s}.select() : Refusing to yield {:d} global tag{:s} for {:s} ({:#x}) possibly due to cache inconsistency as it is not referencing one of the candidate locations ({:s}).".format(__name__, len(tags), '' if len(tags) == 1 else 's', 'function address' if interface.function.has(ea) else 'address', ea, ', '.join(map("{:#x}".format, owners))))
        return

    # Collect the tagnames to query as specified by the user.
    included, required = ({item for item in itertools.chain(*(boolean.get(B, []) for B in Bs))} for Bs in [['include', 'included', 'includes', 'Or'], ['require', 'required', 'requires', 'And']])

    # Walk through every tagged address so we can cross-check them with the query.
    for ea in internal.comment.globals.address():
        collected, _ = {}, ui.navigation.set(ea)
        Ftag, owners = (internal.tags.function.get, {f for f in interface.function.owners(ea)}) if interface.function.has(ea) else (internal.tags.address.get, {ea})
        tags = Ftag(ea)

        # included is the equivalent of Or(|) and yields the address if any of the tagnames are used.
        collected.update({key : value for key, value in tags.items() if key in included})

        # required is the equivalent of And(&) which yields the address only if it uses all of the specified tagnames.
        if required:
            if required & six.viewkeys(tags) == required:
                collected.update({key : value for key, value in tags.items() if key in required})
            else: continue

        # If we collected anything (matches), then yield the address and the matching tags.
        if collected and ea in owners: yield ea, collected
        elif ea not in owners: logging.info(u"{:s}.select({:s}) : Refusing to select from {:d} global tag{:s} for {:s} ({:#x}) possibly due to cache inconsistency as it is not referencing one of the candidate locations ({:s}).".format(__name__, utils.string.kwargs(boolean), len(tags), '' if len(tags) == 1 else 's', 'function address' if interface.function.has(ea) else 'address', ea, ', '.join(map("{:#x}".format, owners))))
    return

@utils.multicase(tag=internal.types.string)
@utils.string.decorate_arguments('tag', 'And', 'Or', 'require', 'requires', 'required', 'include', 'includes', 'included')
def selectcontents(tag, *included, **boolean):
    '''Query the contents of each function for the given `tag` or any others that may be `included`.'''
    res = {tag} | {item for item in included}
    boolean['included'] = {item for item in boolean.get('included', [])} | res
    return selectcontents(**boolean)
@utils.multicase()
@utils.string.decorate_arguments('And', 'Or', 'require', 'requires', 'required', 'include', 'includes', 'included')
def selectcontents(**boolean):
    """Query the contents of each function for any of the tags specified by `boolean` and yield a tuple for each matching function address with selected tags.

    If `require` is given as an iterable of tag names then require that each returned function uses them.
    If `include` is given as an iterable of tag names then include the specified tags for each returned function if available.
    """
    boolean = {key : {item for item in value} if isinstance(value, internal.types.unordered) else {value} for key, value in boolean.items()}

    # Nothing specific was queried, so just yield all tagnames that are available.
    if not boolean:
        for ea, _ in internal.comment.contents.iterate():
            if interface.function.has(ui.navigation.procedure(ea)):
                contents, owners, Flogging = internal.comment.contents.name(ea, target=ea), {f for f in interface.function.owners(ea)}, logging.info
            else:
                contents, owners, Flogging = [], {f for f in []}, logging.warning
            if contents and ea in owners: yield ea, contents
            elif ea not in owners: Flogging(u"{:s}.selectcontents() : Refusing to yield {:d} contents tag{:s} for {:s} ({:#x}) possibly due to cache inconsistency as it is not referencing {:s}.".format(__name__, len(contents), '' if len(contents) == 1 else 's', 'function address' if interface.function.has(ea) else 'address', ea, "a candidate function address ({:s})".format(', '.join(map("{:#x}".format, owners)) if owners else 'a function')))
        return

    # Collect each potential parameter into sets for checking tag membership.
    included, required = ({item for item in itertools.chain(*(boolean.get(B, []) for B in Bs))} for Bs in [['include', 'included', 'includes', 'Or'], ['require', 'required', 'requires', 'And']])

    # Walk through the index verifying that they're within a function. This
    # way we can cross-check their cache against the user's query.
    for ea, cache in internal.comment.contents.iterate():
        if interface.function.has(ui.navigation.procedure(ea)):
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
        collected, names, owners = {item for item in []}, internal.comment.contents.name(ea, target=ea), {item for item in interface.function.owners(ea)}

        # included is the equivalent of Or(|) and yields the function address if any of the specified tagnames were used.
        collected.update(included & names)

        # required is the equivalent of And(&) which yields the function address only if it uses all of the specified tagnames.
        if required:
            if required & names == required:
                collected.update(required)
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

        `address` or `ea` - Filter the imports by an address or a list of addresses
        `name` - Filter the imports by a name or a list of names
        `module` - Filter the imports according to the specified module name
        `fullname` - Filter the full name (module + symbol) of each import with a glob
        `like` - Filter the symbol names of all the imports according to a glob
        `bounds` - Filter the imports within the given boundaries
        `regex` - Filter the symbol names of all the imports according to a regular-expression
        `ordinal` - Filter the imports by the import hint (ordinal) or a list of hints
        `typed` - Filter all of the imports based on whether they have a type applied to them
        `tagged` - Filter the imports for any that use the specified tag(s)
        `predicate` Filter the imports by passing the above (default) tuple to a callable

    Some examples of using these keywords are as follows::

        > database.imports.list(module='kernelbase.dll')
        > iterable = database.imports.iterate(like='*alloc*')
        > result = database.imports.search(index=42)

    """
    def __new__(cls, *string, **type):
        '''Return the imports within the database as a list of tuples that are packed as `(address, (module, name, ordinal))`.'''
        return [item for item in cls.iterate(*string, **type)]

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

        # define all of the formats for the symbols on various platforms.
        gdb_format = u"{:s}::{:s}".format
        osx_format = u"{:s}`{:s}".format
        win_format = u"{:s}!{:s}".format

        # examine the filetype instead of the (flag-based) ostype which is used for FLIRT.
        formats = {ft : win_format for ft in [idc.FT_PE, idc.FT_EXE, idc.FT_COFF, idc.FT_WIN, idc.FT_LX, idc.FT_LE, idc.FT_COM, idc.FT_EXE_OLD, idc.FT_COM_OLD]}
        formats.setdefault(idc.FT_MACHO, osx_format) if hasattr(idc, 'FT_MACHO') else None

        # format what we were given and then return it.
        long_formatter = formats.get(information.filetype(), gdb_format)
        return long_formatter(module, name)

    __format__ = __formatl__

    __matcher__ = utils.matcher()
    __matcher__.combinator('address', utils.fcondition(utils.finstance(internal.types.integer))(utils.fpartial(utils.fpartial, operator.eq), utils.fpartial(utils.fpartial, operator.contains)), operator.itemgetter(0))
    __matcher__.alias('ea', 'address')
    __matcher__.combinator('name', utils.fcondition(utils.finstance(internal.types.string))(utils.fcompose(operator.methodcaller('lower'), utils.fpartial(utils.fpartial, operator.eq)), utils.fcompose(utils.fpartial(map, operator.methodcaller('lower')), internal.types.set, utils.fpartial(utils.fpartial, operator.contains))), operator.itemgetter(1), __formats__.__func__, operator.methodcaller('lower'))
    __matcher__.combinator('fullname', utils.fcompose(fnmatch.translate, utils.fpartial(re.compile, flags=re.IGNORECASE), operator.attrgetter('match')), operator.itemgetter(1), __formatl__.__func__)
    __matcher__.combinator('like', utils.fcompose(fnmatch.translate, utils.fpartial(re.compile, flags=re.IGNORECASE), operator.attrgetter('match')), operator.itemgetter(1), __formats__.__func__)
    __matcher__.combinator('module', utils.fcondition(utils.finstance(internal.types.string))(utils.fcompose(operator.methodcaller('lower'), utils.fpartial(utils.fpartial, operator.eq)), utils.fcompose(utils.fpartial(map, operator.methodcaller('lower')), internal.types.set, utils.fpartial(utils.fpartial, operator.contains))), operator.itemgetter(1), operator.itemgetter(0), operator.methodcaller('lower'))
    __matcher__.combinator('ordinal', utils.fcondition(utils.finstance(internal.types.integer))(utils.fpartial(utils.fpartial, operator.eq), utils.fpartial(utils.fpartial, operator.contains)), operator.itemgetter(1), operator.itemgetter(-1))
    __matcher__.combinator('regex', utils.fcompose(utils.fpartial(re.compile, flags=re.IGNORECASE), operator.attrgetter('match')), operator.itemgetter(1), __format__.__func__)
    __matcher__.mapping('typed', operator.truth, operator.itemgetter(0), lambda ea: idaapi.get_tinfo2(ea, idaapi.tinfo_t()) if idaapi.__version__ < 7.0 else idaapi.get_tinfo(idaapi.tinfo_t(), ea))
    __matcher__.boolean('tagged', lambda parameter, keys: operator.truth(keys) == parameter if isinstance(parameter, internal.types.bool) else operator.contains(keys, parameter) if isinstance(parameter, internal.types.string) else keys & internal.types.set(parameter), operator.itemgetter(0), internal.tags.address.get, operator.methodcaller('keys'), internal.types.set)
    __matcher__.combinator('bounds', utils.fcondition(utils.finstance(interface.bounds_t))(operator.attrgetter('contains'), utils.fcompose(utils.funpack(interface.bounds_t), operator.attrgetter('contains'))), operator.itemgetter(0))
    __matcher__.predicate('predicate'), __matcher__.alias('pred', 'predicate')

    @classmethod
    def __iterate__(cls):
        '''Iterate through the imports within the database yielding a tuple packed as `(address, (module, name, ordinal))` for each iteration.'''
        for idx in builtins.range(idaapi.get_import_module_qty()):
            module = idaapi.get_import_module_name(idx)
            listable = []
            idaapi.enum_import_names(idx, utils.fcompose(lambda *items: items, listable.append, utils.fconstant(True)))
            for ea, name, ordinal in listable:
                ui.navigation.set(ea)
                module_name_ordinal = module, name, ordinal
                realmodule, realname = cls.__symbol__(module_name_ordinal)
                yield ea, (utils.string.of(realmodule), utils.string.of(realname), ordinal)
            continue
        return

    @utils.multicase(name=internal.types.string)
    @classmethod
    @utils.string.decorate_arguments('name')
    def iterate(cls, name):
        '''Iterate through the imports from the database that match the glob specified by `name`.'''
        return cls.iterate(like=name)
    @utils.multicase(bounds=interface.bounds_t)
    @classmethod
    def iterate(cls, bounds):
        '''Iterate through the imports from the database that are contained within the given `bounds`.'''
        return cls.iterate(predicate=operator.truth, bounds=bounds)
    @utils.multicase()
    @classmethod
    @utils.string.decorate_arguments('name', 'module', 'fullname', 'like', 'regex')
    def iterate(cls, **type):
        '''Iterate through the imports from the database that match the keywords specified by `type`.'''
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
    @utils.multicase(ea=internal.types.integer)
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
        raise E.MissingTypeOrAttribute(u"{:s}.at({:#x}) : No import was found at the specified address ({:#x}).".format('.'.join([__name__, cls.__name__]), ea, ea))

    @utils.multicase()
    @classmethod
    @utils.string.decorate_arguments('name', 'module', 'fullname')
    def has(cls, **type):
        '''Return whether the current address is referring to an import.'''
        if 'module' in type:
            module, iterable = type['module'].lower(), (idaapi.get_import_module_name(index) for index in builtins.range(idaapi.get_import_module_qty()))
            return any(utils.string.of(item).lower() == module for item in iterable if name is not None)
        elif type:
            raise E.InvalidParameterError(u"{:s}.has({:s}) : The given keyword parameter{:s} not supported.".format('.'.join([__name__, cls.__name__]), utils.string.kwargs(type), ' is' if len(type) == 1 else 's are'))
        return cls.has(ui.current.address())
    @utils.multicase(ea=internal.types.integer)
    @classmethod
    def has(cls, ea):
        '''Return whether the address `ea` is referring to an import.'''
        return idaapi.segtype(ea) == idaapi.SEG_XTRN and any(address == ea for address, _ in cls.__iterate__())

    @utils.multicase()
    @classmethod
    def module(cls):
        '''Return the import module at the current address.'''
        return cls.module(ui.current.address())
    @utils.multicase(ea=internal.types.integer)
    @classmethod
    def module(cls, ea):
        '''Return the import module at the specified address `ea`.'''
        ea = interface.address.inside(ea)
        for addr, (module, _, _) in cls.__iterate__():
            if addr == ea:
                return module
            continue
        raise E.MissingTypeOrAttribute(u"{:s}.module({:#x}) : No import was found at the specified address ({:#x}).".format('.'.join([__name__, cls.__name__]), ea, ea))

    # specific parts of the import
    @utils.multicase()
    @classmethod
    def fullname(cls):
        '''Return the full name of the import at the current address.'''
        return cls.fullname(ui.current.address())
    @utils.multicase(ea=internal.types.integer)
    @classmethod
    def fullname(cls, ea):
        '''Return the full name of the import at address `ea`.'''
        return cls.__formatl__(cls.at(ea))

    @utils.multicase()
    @classmethod
    def name(cls):
        '''Return the name of the import at the current address.'''
        return cls.name(ui.current.address())
    @utils.multicase(ea=internal.types.integer)
    @classmethod
    def name(cls, ea):
        '''Return the name of the import at address `ea`.'''
        return cls.__formats__(cls.at(ea))

    @utils.multicase()
    @classmethod
    def ordinal(cls):
        '''Return the ordinal of the import at the current address.'''
        return cls.ordinal(ui.current.address())
    @utils.multicase(ea=internal.types.integer)
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

    @utils.multicase(symbol=internal.types.string)
    @classmethod
    @utils.string.decorate_arguments('symbol')
    def list(cls, symbol):
        '''List the imports from the database that match the glob specified by `symbol`.'''
        return cls.list(fullname=symbol)
    @utils.multicase(bounds=interface.bounds_t)
    @classmethod
    def list(cls, bounds):
        '''List the imports from the database within the given `bounds`.'''
        return cls.list(predicate=operator.truth, bounds=bounds)
    @utils.multicase()
    @classmethod
    @utils.string.decorate_arguments('name', 'module', 'fullname', 'like', 'regex')
    def list(cls, **type):
        '''List the imports from the database that match the keywords specified by `type`.'''
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
        prefix, get_tinfo = idaapi.FUNC_IMPORT_PREFIX, (lambda ti, ea: idaapi.get_tinfo2(ea, ti)) if idaapi.__version__ < 7.0 else idaapi.get_tinfo
        for ea, (module, name, ordinal) in listable:
            ui.navigation.set(ea)
            moduleordinal = "{:s}<{:d}>".format(module or '', ordinal) if ordinal else (module or '')

            address_s = "{:<#0{:d}x}".format(ea, 2 + math.trunc(caddr))
            module_s = "{:>{:d}s}".format(moduleordinal if module else '', maxmodule + (2 + cordinal if has_ordinal else 0))

            # Clean up the name and then figure out what the actual name would be. We first
            # strip out the import prefix, then figure out the type before we render just the name.
            name = name[len(prefix):] if name.startswith(prefix) else name
            mangled_name_type_t = Fmangled_type(utils.string.to(name))
            realname = name if mangled_name_type_t == MANGLED_UNKNOWN else utils.string.of(idaapi.demangle_name(utils.string.to(name), MNG_NODEFINIT|MNG_NOPTRTYP) or name)

            # Some flags that are probably useful.
            ftyped = 'T' if get_tinfo(idaapi.tinfo_t(), ea) else 't' if t.has(ea) else '-'
            fordinaled = 'H' if ordinal > 0 else '-'

            tags = internal.tags.address.get(ea)
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

    @utils.multicase(fullname=internal.types.string)
    @classmethod
    @utils.string.decorate_arguments('fullname')
    def search(cls, fullname):
        '''Search through the imports within the database that match the glob specified by `fullname`.'''
        return cls.search(predicate=operator.truth, fullname=fullname)
    @utils.multicase()
    @classmethod
    @utils.string.decorate_arguments('name', 'module', 'fullname', 'like', 'regex')
    def search(cls, **type):
        '''Search through the imports within the database and return the first result matching the keywords specified by `type`.'''
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
        if operator.eq(*(interface.address.head(ea) for ea in selection)):
            return cls.head(address)
        start, stop = selection
        return [ea for ea in cls.iterate(start, stop)]
    @utils.multicase(step=internal.types.callable)
    def __new__(cls, step):
        '''Return a list of each address from the current selection using the callable `step` to find the next address.'''
        address, selection = ui.current.address(), ui.current.selection()
        start, stop = (address, address) if operator.eq(*(interface.address.head(ea) for ea in selection)) else selection
        if operator.sub(*sorted([start, stop])[::-1]) == 0:
            logging.warning(u"{:s}({!s}) : There are {:d} bytes currently selected around address {:#x} which will result in an empty range being returned.".format('.'.join([__name__, cls.__name__]), utils.pycompat.fullname(step), operator.sub(*sorted([start, stop])[::-1]), address))
        return [ea for ea in cls.iterate(start, stop, step)]
    @utils.multicase(ea=internal.types.integer)
    def __new__(cls, ea):
        '''Return the address of the item containing the address `ea`.'''
        return cls.head(ea)
    @utils.multicase(name=internal.types.string)
    @utils.string.decorate_arguments('name', 'suffix')
    def __new__(cls, name, *suffix):
        '''Return the address of the item with the specified `name`.'''
        res = (name,) + suffix
        string = interface.tuplename(*res)
        ea = idaapi.get_name_ea(idaapi.BADADDR, utils.string.to(string))
        if ea == idaapi.BADADDR:
            raise E.AddressNotFoundError(u"{:s}({!r}) : Unable to find the address for the specified symbol \"{:s}\".".format('.'.join([__name__, cls.__name__]), res if suffix else string, utils.string.escape(string, '"')))
        return ea
    @utils.multicase(start=internal.types.integer, stop=internal.types.integer)
    def __new__(cls, start, stop):
        '''Return a list of each address from `start` until the address `stop`.'''
        return [ea for ea in cls.iterate(start, stop)]
    @utils.multicase(start=internal.types.integer, stop=internal.types.integer, step=internal.types.callable)
    def __new__(cls, start, stop, step):
        '''Return a list of each address from `start` until the address `stop` using the callable `step` to find the next address.'''
        return [ea for ea in cls.iterate(start, stop, step)]
    @utils.multicase(bounds=interface.bounds_t)
    def __new__(cls, bounds):
        '''Return a list of each address within the given `bounds`.'''
        return [ea for ea in cls.iterate(bounds)]
    @utils.multicase(bounds=interface.bounds_t, step=internal.types.callable)
    def __new__(cls, bounds, step):
        '''Return a list of each address within the given `bounds` using the callable `step` to find the next address.'''
        return [ea for ea in cls.iterate(bounds, step)]

    @utils.multicase()
    @classmethod
    def bounds(cls):
        '''Return the bounds of the current address or selection in a tuple formatted as `(left, right)`.'''
        address, selection = ui.current.address(), ui.current.selection()
        if operator.eq(*(interface.address.head(ea) for ea in selection)):
            return cls.bounds(address)
        return interface.bounds_t(*selection)
    @utils.multicase(ea=internal.types.integer)
    @classmethod
    def bounds(cls, ea):
        '''Return the bounds of the specified address `ea` in a tuple formatted as `(left, right)`.'''
        return interface.bounds_t(ea, ea + interface.address.size(ea))

    @utils.multicase()
    @classmethod
    def iterate(cls):
        '''Iterate through the currently selected addresses.'''
        selection = ui.current.selection()
        return cls.iterate(selection)
    @utils.multicase(step=internal.types.callable)
    @classmethod
    def iterate(cls, step):
        '''Iterate through the currently selected addresses using the callable `step` to find the next address.'''
        selection = ui.current.selection()
        return cls.iterate(selection, step)
    @utils.multicase(stop=internal.types.integer)
    @classmethod
    def iterate(cls, stop):
        '''Iterate from the current address to until right before the address `stop`.'''
        return cls.iterate(ui.current.address(), stop)
    @utils.multicase(stop=internal.types.integer, step=internal.types.callable)
    @classmethod
    def iterate(cls, stop, step):
        '''Iterate from the current address to the address `stop` using the callable `step` to find the next address.'''
        return cls.iterate(ui.current.address(), stop, step)
    @utils.multicase(start=internal.types.integer, stop=internal.types.integer)
    @classmethod
    def iterate(cls, start, stop):
        '''Iterate from the address `start` until right before the address `stop`.'''
        left, right = interface.address.within(*sorted([start, stop]))
        ea, step, Fwhile = (left, idaapi.next_not_tail, functools.partial(operator.gt, right)) if start <= stop else (right, idaapi.prev_not_tail, functools.partial(operator.le, left))
        iterable = itertools.takewhile(Fwhile, interface.address.iterate(ea, step))
        return itertools.chain([ea], iterable)
    @utils.multicase(start=internal.types.integer, stop=internal.types.integer, step=internal.types.callable)
    @classmethod
    def iterate(cls, start, stop, step):
        '''Iterate from address `start` until the address `stop` using the callable `step` to find the next address.'''
        left, right = interface.address.within(*sorted([start, stop]))
        Fwhile, Fwalk = (functools.partial(operator.gt, right), interface.address.walk_forward) if start <= stop else (functools.partial(operator.le, left), interface.address.walk_backward)
        iterable = (ui.navigation.set(ea) for ea in Fwalk(start, step))
        return itertools.takewhile(Fwhile, iterable)
    @utils.multicase(location=interface.location_t)
    @classmethod
    def iterate(cls, location):
        '''Iterate through all of the addresses defined within the specified `location`.'''
        bounds = location.bounds
        return cls.iterate(bounds)
    @utils.multicase(location=interface.location_t, step=internal.types.callable)
    @classmethod
    def iterate(cls, location, step):
        '''Iterate through all of the addresses defined within the specified `location`.'''
        bounds = location.bounds
        return cls.iterate(bounds, step)
    @utils.multicase(bounds=interface.bounds_t)
    @classmethod
    def iterate(cls, bounds):
        '''Iterate through all of the addresses defined within `bounds`.'''
        start, stop = bounds
        return cls.iterate(start, stop)
    @utils.multicase(bounds=interface.bounds_t, step=internal.types.callable)
    @classmethod
    def iterate(cls, bounds, step):
        '''Iterate through all of the addresses defined within `bounds` using the callable `step` to find the next address.'''
        left, right = bounds
        return cls.iterate(left, right, step)

    @utils.multicase()
    @classmethod
    def blocks(cls):
        '''Iterate through the currently selected blocks.'''
        selection = ui.current.selection()
        return cls.blocks(selection)
    @utils.multicase(stop=internal.types.integer)
    @classmethod
    def blocks(cls, stop):
        '''Yields the boundaries of each block from the current address until the address `stop`.'''
        return cls.blocks(ui.current.address(), stop)
    @utils.multicase(bounds=interface.bounds_t)
    @classmethod
    def blocks(cls, bounds):
        '''Yields the boundaries of each block within the specified `bounds`.'''
        left, right = bounds
        return cls.blocks(left, right)
    @utils.multicase(start=internal.types.integer, stop=internal.types.integer)
    @classmethod
    def blocks(cls, start, stop):
        '''Yields the boundaries of each block from the address `start` until the address `stop`.'''
        block, _ = start, stop = interface.address.head(start, warn=True), interface.address.tail(stop, warn=False) + 1

        results = []
        for ea in cls.iterate(start, stop):
            nextea = cls.next(ea)

            ## XXX: it seems that idaapi.is_basic_block_end requires the following to be called
            # idaapi.decode_insn(insn, ea)
            ## XXX: for some reason is_basic_block_end will occasionally include some stray 'call' instructions
            # if idaapi.is_basic_block_end(ea):
            #     yield block, nextea
            ## XXX: in later versions of ida, is_basic_block_end takes two args (ea, bool call_insn_stops_block)

            # call and halting instructions will terminate a block
            if interface.instruction.is_call(ea) or interface.instruction.is_return(ea):
                results.append(interface.bounds_t(block, nextea))
                block = nextea

            # branch instructions will terminate a block
            elif interface.instruction.is_branch(ea):
                results.append(interface.bounds_t(block, nextea))
                block = nextea
            continue
        return results

    @utils.multicase()
    @classmethod
    def head(cls):
        '''Return the address of the byte at the beginning of the current address.'''
        return cls.head(ui.current.address())
    @utils.multicase(ea=internal.types.integer)
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
    @utils.multicase(ea=internal.types.integer)
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
    @utils.multicase(predicate=internal.types.callable)
    @classmethod
    def prev(cls, predicate, **count):
        '''Return the previous address from the current address that satisfies the provided `predicate`.'''
        return cls.prev(ui.current.address(), predicate, **count)
    @utils.multicase(ea=internal.types.integer)
    @classmethod
    def prev(cls, ea):
        '''Return the previous address from the address specified by `ea`.'''
        return cls.prev(ea, 1)
    @utils.multicase(ea=internal.types.integer, predicate=internal.types.callable)
    @classmethod
    def prev(cls, ea, predicate):
        '''Return the previous address from the address `ea` that satisfies the provided `predicate`.'''
        return cls.prevF(ea, predicate, 1)
    @utils.multicase(ea=internal.types.integer, count=internal.types.integer)
    @classmethod
    def prev(cls, ea, count):
        '''Return the previous `count` addresses from the address specified by `ea`.'''
        return cls.prevF(ea, utils.fidentity, count)
    @utils.multicase(ea=internal.types.integer, predicate=internal.types.callable, count=internal.types.integer)
    @classmethod
    def prev(cls, ea, predicate, count):
        '''Return the previous `count` addresses from the address `ea` that satisfies the provided `predicate`.'''
        return cls.prevF(ea, predicate, count)

    @utils.multicase()
    @classmethod
    def next(cls, **count):
        '''Return the next address from the current address.'''
        return cls.next(ui.current.address(), count.pop('count', 1))
    @utils.multicase(predicate=internal.types.callable)
    @classmethod
    def next(cls, predicate, **count):
        '''Return the next address from the current address that satisfies the provided `predicate`.'''
        return cls.next(ui.current.address(), predicate, **count)
    @utils.multicase(ea=internal.types.integer)
    @classmethod
    def next(cls, ea):
        '''Return the next address from the address `ea`.'''
        return cls.next(ea, 1)
    @utils.multicase(ea=internal.types.integer, predicate=internal.types.callable)
    @classmethod
    def next(cls, ea, predicate):
        '''Return the next address from the address `ea` that satisfies the provided `predicate`.'''
        return cls.nextF(ea, predicate, 1)
    @utils.multicase(ea=internal.types.integer, count=internal.types.integer)
    @classmethod
    def next(cls, ea, count):
        '''Return the next `count` addresses from the address specified by `ea`.'''
        return cls.nextF(ea, utils.fidentity, count)
    @utils.multicase(ea=internal.types.integer, predicate=internal.types.callable, count=internal.types.integer)
    @classmethod
    def next(cls, ea, predicate, count):
        '''Return the next `count` addresses from the address `ea` that satisfies the provided `predicate`.'''
        return cls.nextF(ea, predicate, count)

    @utils.multicase(predicate=internal.types.callable)
    @classmethod
    def prevF(cls, predicate, **count):
        '''Return the previous address from the current one that satisfies the provided `predicate`.'''
        return cls.prevF(ui.current.address(), predicate, count.pop('count', 1))
    @utils.multicase(ea=internal.types.integer, predicate=internal.types.callable)
    @classmethod
    def prevF(cls, ea, predicate, **count):
        '''Return the previous address from the address `ea` that satisfies the provided `predicate`.'''
        return cls.prevF(ea, predicate, count.pop('count', 1))
    @utils.multicase(ea=internal.types.integer, predicate=internal.types.callable, count=internal.types.integer)
    @classmethod
    def prevF(cls, ea, predicate, count):
        '''Return the previous `count` addresses from the address `ea` that satisfies the provided `predicate`.'''
        top, bottom = information.bounds()
        ea, Fstart, Fprev = (ea, functools.partial(operator.sub, 1), idaapi.prev_not_tail) if ea == bottom else (interface.address.within(ea), idaapi.get_item_head, idaapi.prev_not_tail)

        # if we're already at the top, there's nowhere else to go.
        if Fprev(ea) == idaapi.BADADDR:
            raise E.AddressOutOfBoundsError(u"{:s}.prevF({:#x}, {!r}, {:d}): Refusing to seek past the top of the database ({:#x}). Stopped at address {:#x}.".format('.'.join([__name__, cls.__name__]), ea, predicate, count, top, ea))

        # grab all of the matching addresses and return the very last one.
        iterable = (item for item in interface.address.iterate(Fstart(ea), Fprev) if predicate(ui.navigation.analyze(item)))
        items = [item for index, item in zip(builtins.range(count), iterable)]

        # if we didn't retrieve enough items, then we seeked past the top of the database.
        if count and len(items) < count:
            raise E.AddressOutOfBoundsError(u"{:s}.prevF({:#x}, {!r}, {:d}): Refusing to seek past the top of the database ({:#x}). Stopped at address {:#x}.".format('.'.join([__name__, cls.__name__]), ea, predicate, count, top, items[-1] if items else ea))
        return items[-1] if items else ea

    @utils.multicase(predicate=internal.types.callable)
    @classmethod
    def nextF(cls, predicate, **count):
        '''Return the next address from the current one that satisfies the provided `predicate`.'''
        return cls.nextF(ui.current.address(), predicate, count.pop('count', 1))
    @utils.multicase(ea=internal.types.integer, predicate=internal.types.callable)
    @classmethod
    def nextF(cls, ea, predicate, **count):
        '''Return the next address from the address `ea` that satisfies the provided `predicate`.'''
        return cls.nextF(ea, predicate, count.pop('count', 1))
    @utils.multicase(ea=internal.types.integer, predicate=internal.types.callable, count=internal.types.integer)
    @classmethod
    def nextF(cls, ea, predicate, count):
        '''Return the next `count` addresses from the address `ea` that satisfies the provided `predicate`.'''
        top, bottom = information.bounds()
        ea, Fnext = (ea, idaapi.next_not_tail) if ea == top else (interface.address.within(ea), idaapi.next_not_tail)

        # if we're already at the bottom, there's nowhere else to go.
        if Fnext(ea) == idaapi.BADADDR:
            raise E.AddressOutOfBoundsError(u"{:s}.nextF({:#x}, {!r}, {:d}): Refusing to seek past the bottom of the database ({:#x}). Stopped at address {:#x}.".format('.'.join([__name__, cls.__name__]), ea, predicate, count, bottom, idaapi.get_item_end(ea)))

        # grab all of the matching addresses and return the very last one.
        iterable = (item for item in interface.address.iterate(idaapi.get_item_head(ea), Fnext) if predicate(ui.navigation.analyze(item)))
        items = [item for index, item in zip(builtins.range(count), iterable)]

        # if we didn't retrieve enough items, then we seeked past the top of the database.
        if count and len(items) < count:
            raise E.AddressOutOfBoundsError(u"{:s}.nextF({:#x}, {!r}, {:d}): Refusing to seek past the bottom of the database ({:#x}). Stopped at address {:#x}.".format('.'.join([__name__, cls.__name__]), ea, predicate, count, bottom, items[-1] if items else ea))
        return items[-1] if items else ea

    @utils.multicase(mask=(internal.types.integer, internal.types.tuple))
    @classmethod
    def prevflag(cls, mask, **count):
        '''Return the previous address where its flags match the given `mask`.'''
        return cls.prevflag(mask, ui.current.address(), count.pop('count', 1))
    @utils.multicase(mask=(internal.types.integer, internal.types.tuple, internal.types.callable), ea=internal.types.integer)
    @classmethod
    def prevflag(cls, mask, ea):
        '''Return the previous address from the address `ea` where its flags match the given `mask`.'''
        return cls.prevflag(mask, ea, 1)
    @utils.multicase(mask_value=internal.types.tuple, ea=internal.types.integer, predicate=internal.types.callable)
    @classmethod
    def prevflag(cls, mask_value, ea, predicate, **count):
        '''Return the previous address from the address `ea` where its flags match the given `mask_value` and satisfies the given `predicate`.'''
        mask, value = mask_value
        Ftest = utils.fcompose(functools.partial(operator.and_, mask), functools.partial(operator.eq, value))
        return cls.prevflag(Ftest, ea, predicate, **count)
    @utils.multicase(mask=internal.types.integer, ea=internal.types.integer, predicate=internal.types.callable)
    @classmethod
    def prevflag(cls, mask, ea, predicate, **count):
        '''Return the previous address from the address `ea` where its flags match the given `mask`.'''
        return cls.prevflag(functools.partial(operator.and_, mask), ea, predicate, **count)
    @utils.multicase(test=internal.types.callable, ea=internal.types.integer, predicate=internal.types.callable)
    @classmethod
    def prevflag(cls, test, ea, predicate, **count):
        '''Return the previous address from the address `ea` that satisfies the given `predicate` and a flag satisfying the given `test`.'''
        counter, Fprev_that = max(1, count.get('count', 1)), idaapi.prev_that if hasattr(idaapi, 'prev_that') else idaapi.prevthat
        while counter > 0:
            next = Fprev_that(ea, 0, test)
            if next == idaapi.BADADDR:
                raise E.AddressOutOfBoundsError(u"{:s}.prevflag({!s}, {:#x}, {!s}{:s}): Refusing to seek past the top of the database ({:#x}). Stopped at address {:#x}.".format('.'.join([__name__, cls.__name__]), test, ea, predicate, ", {:s}".format(utils.string.kwargs(count)) if count else '', top(), ea))
            elif predicate(next):
                counter -= 1
            ea = next
        return ea
    @utils.multicase(mask_value=internal.types.tuple, ea=internal.types.integer, count=internal.types.integer)
    @classmethod
    def prevflag(cls, mask_value, ea, count):
        '''Return the previous `count` addresses from the address `ea` where its flags match the given `mask_value`.'''
        mask, value = mask_value
        Ftest = utils.fcompose(functools.partial(operator.and_, mask), functools.partial(operator.eq, value))
        return cls.prevflag(Ftest, ea, count)
    @utils.multicase(mask=internal.types.integer, ea=internal.types.integer, count=internal.types.integer)
    @classmethod
    def prevflag(cls, mask, ea, count):
        '''Return the previous `count` addresses from the address `ea` where its flags match the given `mask`.'''
        return cls.prevflag(functools.partial(operator.and_, mask), ea, count)
    @utils.multicase(test=internal.types.callable, ea=internal.types.integer, count=internal.types.integer)
    @classmethod
    def prevflag(cls, test, ea, count):
        '''Return the previous `count` addresses from the address `ea` that has a flag satisfying the given `test`.'''
        Fprev_that = idaapi.prev_that if hasattr(idaapi, 'prev_that') else idaapi.prevthat
        for index in builtins.range(max(1, count)):
            next = Fprev_that(ea, 0, test)
            if next == idaapi.BADADDR:
                raise E.AddressOutOfBoundsError(u"{:s}.prevflag({!s}, {:#x}, {:d}): Refusing to seek past the top of the database ({:#x}). Stopped at address {:#x}.".format('.'.join([__name__, cls.__name__]), test, ea, count, top(), ea))
            ea = next
        return ea

    @utils.multicase(mask=(internal.types.integer, internal.types.tuple))
    @classmethod
    def nextflag(cls, mask, **count):
        '''Return the next address where its flags match the given `mask`.'''
        return cls.nextflag(mask, ui.current.address(), count.pop('count', 1))
    @utils.multicase(mask=(internal.types.integer, internal.types.tuple, internal.types.callable), ea=internal.types.integer)
    @classmethod
    def nextflag(cls, mask, ea):
        '''Return the next address from the address `ea` where its flags match the given `mask`.'''
        return cls.nextflag(mask, ea, 1)
    @utils.multicase(mask_value=internal.types.tuple, ea=internal.types.integer, predicate=internal.types.callable)
    @classmethod
    def nextflag(cls, mask_value, ea, predicate, **count):
        '''Return the next address from the address `ea` where its flags match the given `mask_value` and satisfies the given `predicate`.'''
        mask, value = mask_value
        Ftest = utils.fcompose(functools.partial(operator.and_, mask), functools.partial(operator.eq, value))
        return cls.nextflag(Ftest, ea, predicate, **count)
    @utils.multicase(mask=internal.types.integer, ea=internal.types.integer, predicate=internal.types.callable)
    @classmethod
    def nextflag(cls, mask, ea, predicate, **count):
        '''Return the next address from the address `ea` where its flags match the given `mask`.'''
        return cls.nextflag(functools.partial(operator.and_, mask), ea, predicate, **count)
    @utils.multicase(test=internal.types.callable, ea=internal.types.integer, predicate=internal.types.callable)
    @classmethod
    def nextflag(cls, test, ea, predicate, **count):
        '''Return the next address from the address `ea` that satisfies the given `predicate` and a flag satisfying the given `test`.'''
        next, counter, Fnext_that = ~ea, max(1, count.get('count', 1)), idaapi.next_that if hasattr(idaapi, 'next_that') else idaapi.nextthat
        while counter > 0:
            next = Fnext_that(ea + 1 if next == ea else ea, idaapi.BADADDR, test)
            if next == idaapi.BADADDR:
                raise E.AddressOutOfBoundsError(u"{:s}.nextflag({!s}, {:#x}, {!s}{:s}): Refusing to seek past the bottom of the database ({:#x}). Stopped at address {:#x}.".format('.'.join([__name__, cls.__name__]), test, ea, predicate, ", {:s}".format(utils.string.kwargs(count)) if count else '', bottom(), ea))
            elif predicate(next):
                counter -= 1
            ea = next
        return ea
    @utils.multicase(mask_value=internal.types.tuple, ea=internal.types.integer, count=internal.types.integer)
    @classmethod
    def nextflag(cls, mask_value, ea, count):
        '''Return the next `count` addresses from the address `ea` where its flags match the given `mask_value`.'''
        mask, value = mask_value
        Ftest = utils.fcompose(functools.partial(operator.and_, mask), functools.partial(operator.eq, value))
        return cls.nextflag(Ftest, ea, count)
    @utils.multicase(mask=internal.types.integer, ea=internal.types.integer, count=internal.types.integer)
    @classmethod
    def nextflag(cls, mask, ea, count):
        '''Return the next `count` addresses from the address `ea` where its flags match the given `mask`.'''
        return cls.nextflag(functools.partial(operator.and_, mask), ea, count)
    @utils.multicase(test=internal.types.callable, ea=internal.types.integer, count=internal.types.integer)
    @classmethod
    def nextflag(cls, test, ea, count):
        '''Return the next `count` addresses from the address `ea` that has a flag satisfying the given `test`.'''
        next, Fnext_that = ~ea, idaapi.next_that if hasattr(idaapi, 'next_that') else idaapi.nextthat
        for index in builtins.range(max(1, count)):
            next = Fnext_that(ea + 1 if next == ea else ea, idaapi.BADADDR, test)
            if next == idaapi.BADADDR:
                raise E.AddressOutOfBoundsError(u"{:s}.nextflag({!s}, {:#x}, {:d}): Refusing to seek past the bottom of the database ({:#x}). Stopped at address {:#x}.".format('.'.join([__name__, cls.__name__]), test, ea, count, bottom(), ea))
            ea = next
        return ea

    @utils.multicase()
    @classmethod
    def prevdata(cls, **count):
        '''Return the previous address that is defined as data.'''
        return cls.prevdata(ui.current.address(), count.pop('count', 1))
    @utils.multicase(predicate=internal.types.callable)
    @classmethod
    def prevdata(cls, predicate, **count):
        '''Return the previous address that is defined as data and satisfies the provided `predicate`.'''
        return cls.prevdata(ui.current.address(), predicate, **count)
    @utils.multicase(ea=internal.types.integer, predicate=internal.types.callable)
    @classmethod
    def prevdata(cls, ea, predicate, **count):
        '''Return the previous address from the address `ea` that is defined as data and satisfies the provided `predicate`.'''
        counter = max(1, count.get('count', 1))
        while counter > 0:
            next = idaapi.find_data(ea, idaapi.SEARCH_UP)
            if next == idaapi.BADADDR:
                raise E.AddressOutOfBoundsError(u"{:s}.prevdata({:#x}, {!s}{:s}): Refusing to seek past the top of the database ({:#x}). Stopped at address {:#x}.".format('.'.join([__name__, cls.__name__]), ea, predicate, ", {:s}".format(utils.string.kwargs(count)) if count else '', top(), ea))
            elif predicate(next):
                counter -= 1
            ea = next
        return ea
    @utils.multicase(ea=internal.types.integer)
    @classmethod
    def prevdata(cls, ea):
        '''Return the previous address from the address `ea` that is defined as data.'''
        res = idaapi.find_data(ea, idaapi.SEARCH_UP)
        if res == idaapi.BADADDR:
            raise E.AddressOutOfBoundsError(u"{:s}.prevdata({:#x}): Refusing to seek past the top of the database ({:#x}). Stopped at address {:#x}.".format('.'.join([__name__, cls.__name__]), ea, top(), ea))
        return res
    @utils.multicase(ea=internal.types.integer, count=internal.types.integer)
    @classmethod
    def prevdata(cls, ea, count):
        '''Return the previous `count` addresses from the address `ea` that is defined as data.'''
        for index in builtins.range(max(1, count)):
            next = idaapi.find_data(ea, idaapi.SEARCH_UP)
            if next == idaapi.BADADDR:
                raise E.AddressOutOfBoundsError(u"{:s}.prevdata({:#x}, {:d}): Refusing to seek past the top of the database ({:#x}). Stopped at address {:#x}.".format('.'.join([__name__, cls.__name__]), ea, count, top(), ea))
            ea = next
        return ea

    @utils.multicase()
    @classmethod
    def nextdata(cls, **count):
        '''Return the next address that is defined as data.'''
        return cls.nextdata(ui.current.address(), count.pop('count', 1))
    @utils.multicase(predicate=internal.types.callable)
    @classmethod
    def nextdata(cls, predicate, **count):
        '''Return the next address that is defined as data and satisfies the provided `predicate`.'''
        return cls.nextdata(ui.current.address(), predicate, **count)
    @utils.multicase(ea=internal.types.integer, predicate=internal.types.callable)
    @classmethod
    def nextdata(cls, ea, predicate, **count):
        '''Return the previous address from the address `ea` that is defined as data and satisfies the provided `predicate`.'''
        counter = max(1, count.get('count', 1))
        while counter > 0:
            next = idaapi.find_data(ea, idaapi.SEARCH_DOWN)
            if next == idaapi.BADADDR:
                raise E.AddressOutOfBoundsError(u"{:s}.nextdata({:#x}, {!s}{:s}): Refusing to seek past the bottom of the database ({:#x}). Stopped at address {:#x}.".format('.'.join([__name__, cls.__name__]), ea, predicate, ", {:s}".format(utils.string.kwargs(count)) if count else '', bottom(), ea))
            elif predicate(next):
                counter -= 1
            ea = next
        return ea
    @utils.multicase(ea=internal.types.integer)
    @classmethod
    def nextdata(cls, ea):
        '''Return the next address from the address `ea` that is defined as data.'''
        res = idaapi.find_data(ea, idaapi.SEARCH_DOWN)
        if res == idaapi.BADADDR:
            raise E.AddressOutOfBoundsError(u"{:s}.nextdata({:#x}): Refusing to seek past the bottom of the database ({:#x}). Stopped at address {:#x}.".format('.'.join([__name__, cls.__name__]), ea, bottom(), idaapi.get_item_end(ea)))
        return res
    @utils.multicase(ea=internal.types.integer, count=internal.types.integer)
    @classmethod
    def nextdata(cls, ea, count):
        '''Return the next `count` addresses from the address `ea` that is defined as data.'''
        for index in builtins.range(max(1, count)):
            next = idaapi.find_data(ea, idaapi.SEARCH_DOWN)
            if next == idaapi.BADADDR:
                raise E.AddressOutOfBoundsError(u"{:s}.nextdata({:#x}, {:d}): Refusing to seek past the bottom of the database ({:#x}). Stopped at address {:#x}.".format('.'.join([__name__, cls.__name__]), ea, count, bottom(), idaapi.get_item_end(ea)))
            ea = next
        return ea

    @utils.multicase()
    @classmethod
    def prevcode(cls, **count):
        '''Return the previous address that is defined as code.'''
        return cls.prevcode(ui.current.address(), count.pop('count', 1))
    @utils.multicase(predicate=internal.types.callable)
    @classmethod
    def prevcode(cls, predicate, **count):
        '''Return the previous address that is defined as code and satisfies the provided `predicate`.'''
        return cls.prevcode(ui.current.address(), predicate, **count)
    @utils.multicase(ea=internal.types.integer, predicate=internal.types.callable)
    @classmethod
    def prevcode(cls, ea, predicate, **count):
        '''Return the previous address from the address `ea` that is defined as code and satisfies the provided `predicate`.'''
        counter = max(1, count.get('count', 1))
        while counter > 0:
            next = idaapi.find_code(ea, idaapi.SEARCH_UP)
            if next == idaapi.BADADDR:
                raise E.AddressOutOfBoundsError(u"{:s}.prevcode({:#x}, {!s}{:s}): Refusing to seek past the top of the database ({:#x}). Stopped at address {:#x}.".format('.'.join([__name__, cls.__name__]), ea, predicate, ", {:s}".format(utils.string.kwargs(count)) if count else '', top(), ea))
            elif predicate(next):
                counter -= 1
            ea = next
        return ea
    @utils.multicase(ea=internal.types.integer)
    @classmethod
    def prevcode(cls, ea):
        '''Return the previous address from the address `ea` that is defined as code.'''
        res = idaapi.find_code(ea, idaapi.SEARCH_UP)
        if res == idaapi.BADADDR:
            raise E.AddressOutOfBoundsError(u"{:s}.prevcode({:#x}): Refusing to seek past the top of the database ({:#x}). Stopped at address {:#x}.".format('.'.join([__name__, cls.__name__]), ea, top(), ea))
        return res
    @utils.multicase(ea=internal.types.integer, count=internal.types.integer)
    @classmethod
    def prevcode(cls, ea, count):
        '''Return the previous `count` addresses from the address `ea` that is defined as code.'''
        for index in builtins.range(max(1, count)):
            next = idaapi.find_code(ea, idaapi.SEARCH_UP)
            if next == idaapi.BADADDR:
                raise E.AddressOutOfBoundsError(u"{:s}.prevcode({:#x}, {:d}): Refusing to seek past the top of the database ({:#x}). Stopped at address {:#x}.".format('.'.join([__name__, cls.__name__]), ea, count, top(), ea))
            ea = next
        return ea

    @utils.multicase()
    @classmethod
    def nextcode(cls, **count):
        '''Return the next address that is defined as code.'''
        return cls.nextcode(ui.current.address(), count.pop('count', 1))
    @utils.multicase(predicate=internal.types.callable)
    @classmethod
    def nextcode(cls, predicate, **count):
        '''Return the next address that is defined as code and satisfies the provided `predicate`.'''
        return cls.nextcode(ui.current.address(), predicate, **count)
    @utils.multicase(ea=internal.types.integer, predicate=internal.types.callable)
    @classmethod
    def nextcode(cls, ea, predicate, **count):
        '''Return the next address from the address `ea` that is defined as code and satisfies the provided `predicate`.'''
        counter = max(1, count.get('count', 1))
        while counter > 0:
            next = idaapi.find_code(ea, idaapi.SEARCH_DOWN)
            if next == idaapi.BADADDR:
                raise E.AddressOutOfBoundsError(u"{:s}.nextcode({:#x}, {!s}{:s}): Refusing to seek past the bottom of the database ({:#x}). Stopped at address {:#x}.".format('.'.join([__name__, cls.__name__]), ea, predicate, ", {:s}".format(utils.string.kwargs(count)) if count else '', bottom(), ea))
            elif predicate(next):
                counter -= 1
            ea = next
        return ea
    @utils.multicase(ea=internal.types.integer)
    @classmethod
    def nextcode(cls, ea):
        '''Return the next address from the address `ea` that is defined as code.'''
        res = idaapi.find_code(ea, idaapi.SEARCH_DOWN)
        if res == idaapi.BADADDR:
            raise E.AddressOutOfBoundsError(u"{:s}.nextcode({:#x}): Refusing to seek past the bottom of the database ({:#x}). Stopped at address {:#x}.".format('.'.join([__name__, cls.__name__]), ea, bottom(), idaapi.get_item_end(ea)))
        return res
    @utils.multicase(ea=internal.types.integer, count=internal.types.integer)
    @classmethod
    def nextcode(cls, ea, count):
        '''Return the next `count` addresses from the address `ea` that is defined as code.'''
        for index in builtins.range(max(1, count)):
            next = idaapi.find_code(ea, idaapi.SEARCH_DOWN)
            if next == idaapi.BADADDR:
                raise E.AddressOutOfBoundsError(u"{:s}.nextcode({:#x}, {:d}): Refusing to seek past the bottom of the database ({:#x}). Stopped at address {:#x}.".format('.'.join([__name__, cls.__name__]), ea, count, bottom(), idaapi.get_item_end(ea)))
            ea = next
        return ea

    @utils.multicase()
    @classmethod
    def prevunknown(cls, **count):
        '''Return the previous address that is undefined.'''
        return cls.prevunknown(ui.current.address(), count.pop('count', 1))
    @utils.multicase(predicate=internal.types.callable)
    @classmethod
    def prevunknown(cls, predicate, **count):
        '''Return the previous address that is undefined and satisfies the provided `predicate`.'''
        return cls.prevunknown(ui.current.address(), predicate, **count)
    @utils.multicase(ea=internal.types.integer, predicate=internal.types.callable)
    @classmethod
    def prevunknown(cls, ea, predicate, **count):
        '''Return the previous address from the address `ea` that is undefined and satisfies the provided `predicate`.'''
        counter = max(1, count.get('count', 1))
        while counter > 0:
            next = idaapi.find_unknown(ea, idaapi.SEARCH_UP)
            if next == idaapi.BADADDR:
                raise E.AddressOutOfBoundsError(u"{:s}.prevunknown({:#x}, {!s}{:s}): Refusing to seek past the top of the database ({:#x}). Stopped at address {:#x}.".format('.'.join([__name__, cls.__name__]), ea, predicate, ", {:s}".format(utils.string.kwargs(count)) if count else '', top(), ea))
            elif predicate(next):
                counter -= 1
            ea = next
        return ea
    @utils.multicase(ea=internal.types.integer)
    @classmethod
    def prevunknown(cls, ea):
        '''Return the previous address from the address `ea` that is undefined.'''
        res = idaapi.find_unknown(ea, idaapi.SEARCH_UP)
        if res == idaapi.BADADDR:
            raise E.AddressOutOfBoundsError(u"{:s}.prevunknown({:#x}): Refusing to seek past the top of the database ({:#x}). Stopped at address {:#x}.".format('.'.join([__name__, cls.__name__]), ea, top(), ea))
        return res
    @utils.multicase(ea=internal.types.integer, count=internal.types.integer)
    @classmethod
    def prevunknown(cls, ea, count):
        '''Return the previous `count` addresses from the address `ea` that is undefined.'''
        for index in builtins.range(max(1, count)):
            next = idaapi.find_unknown(ea, idaapi.SEARCH_UP)
            if next == idaapi.BADADDR:
                raise E.AddressOutOfBoundsError(u"{:s}.prevunknown({:#x}, {:d}): Refusing to seek past the top of the database ({:#x}). Stopped at address {:#x}.".format('.'.join([__name__, cls.__name__]), ea, count, top(), ea))
            ea = next
        return ea

    @utils.multicase()
    @classmethod
    def nextunknown(cls, **count):
        '''Return the next address that is undefined.'''
        return cls.nextunknown(ui.current.address(), count.pop('count', 1))
    @utils.multicase(predicate=internal.types.callable)
    @classmethod
    def nextunknown(cls, predicate, **count):
        '''Return the next address that is undefined and satisfies the provided `predicate`.'''
        return cls.nextunknown(ui.current.address(), predicate, **count)
    @utils.multicase(ea=internal.types.integer, predicate=internal.types.callable)
    @classmethod
    def nextunknown(cls, ea, predicate, **count):
        '''Return the next address from the address `ea` that is undefined and satisfies the provided `predicate`.'''
        counter = max(1, count.get('count', 1))
        while counter > 0:
            next = idaapi.find_unknown(ea, idaapi.SEARCH_DOWN)
            if next == idaapi.BADADDR:
                raise E.AddressOutOfBoundsError(u"{:s}.nextunknown({:#x}, {!s}{:s}): Refusing to seek past the bottom of the database ({:#x}). Stopped at address {:#x}.".format('.'.join([__name__, cls.__name__]), ea, predicate, ", {:s}".format(utils.string.kwargs(count)) if count else '', bottom(), ea))
            elif predicate(next):
                counter -= 1
            ea = next
        return ea
    @utils.multicase(ea=internal.types.integer)
    @classmethod
    def nextunknown(cls, ea):
        '''Return the next address from the address `ea` that is undefined.'''
        res = idaapi.find_unknown(ea, idaapi.SEARCH_DOWN)
        if res == idaapi.BADADDR:
            raise E.AddressOutOfBoundsError(u"{:s}.nextunknown({:#x}): Refusing to seek past the bottom of the database ({:#x}). Stopped at address {:#x}.".format('.'.join([__name__, cls.__name__]), ea, bottom(), idaapi.get_item_end(ea)))
        return res
    @utils.multicase(ea=internal.types.integer, count=internal.types.integer)
    @classmethod
    def nextunknown(cls, ea, count):
        '''Return the next `count` addresses from the address `ea` that is undefined.'''
        for index in builtins.range(max(1, count)):
            next = idaapi.find_unknown(ea, idaapi.SEARCH_DOWN)
            if next == idaapi.BADADDR:
                raise E.AddressOutOfBoundsError(u"{:s}.nextunknown({:#x}, {:d}): Refusing to seek past the bottom of the database ({:#x}). Stopped at address {:#x}.".format('.'.join([__name__, cls.__name__]), ea, count, bottom(), idaapi.get_item_end(ea)))
            ea = next
        return ea

    @utils.multicase(byte=internal.types.integer)
    @classmethod
    def prevbyte(cls, byte, **count):
        '''Return the previous address that uses the specified `byte` value.'''
        return cls.prevbyte(byte, ui.current.address(), count.pop('count', 1))
    @utils.multicase(byte=internal.types.integer, ea=internal.types.integer)
    @classmethod
    def prevbyte(cls, byte, ea):
        '''Return the previous address from the address `ea` that uses the specified `byte` value.'''
        return cls.prevbyte(byte, ea, 1)
    @utils.multicase(byte=internal.types.integer, ea=internal.types.integer, predicate=internal.types.callable)
    @classmethod
    def prevbyte(cls, byte, ea, predicate, **count):
        '''Return the previous address from the address `ea` that uses the specified `byte` value and satisfies the given `predicate`.'''
        counter, parameters = max(1, count.get('count', 1)), [byte, False] if idaapi.__version__ < 7.0 else [byte, idaapi.BIN_SEARCH_BACKWARD | idaapi.BIN_SEARCH_CASE]
        while counter > 0:
            next = idaapi.find_byter(0, ea, *parameters)
            if next == idaapi.BADADDR:
                raise E.AddressOutOfBoundsError(u"{:s}.prevbyte({:#0{:d}x}, {:#x}, {!s}{:s}): Refusing to seek past the top of the database ({:#x}). Stopped at address {:#x}.".format('.'.join([__name__, cls.__name__]), byte, 2 + 2, ea, predicate, ", {:s}".format(utils.string.kwargs(count)) if count else '', top(), ea))
            elif predicate(next):
                counter -= 1
            ea = next
        return ea
    @utils.multicase(byte=internal.types.integer, ea=internal.types.integer, count=internal.types.integer)
    @classmethod
    def prevbyte(cls, byte, ea, count):
        '''Return the previous `count` addresses from the address `ea` that uses the specified `byte` value.'''
        parameters = [byte, False] if idaapi.__version__ < 7.0 else [byte, idaapi.BIN_SEARCH_BACKWARD | idaapi.BIN_SEARCH_CASE]
        for index in builtins.range(max(1, count)):
            next = idaapi.find_byter(0, ea, *parameters)
            if next == idaapi.BADADDR:
                raise E.AddressOutOfBoundsError(u"{:s}.prevbyte({:#0{:d}x}, {:#x}, {:d}): Refusing to seek past the top of the database ({:#x}). Stopped at address {:#x}.".format('.'.join([__name__, cls.__name__]), byte, 2 + 2, ea, count, top(), ea))
            ea = next
        return ea

    @utils.multicase(byte=internal.types.integer)
    @classmethod
    def nextbyte(cls, byte, **count):
        '''Return the next address that uses the specified `byte` value.'''
        return cls.nextbyte(byte, ui.current.address(), count.pop('count', 1))
    @utils.multicase(byte=internal.types.integer, ea=internal.types.integer)
    @classmethod
    def nextbyte(cls, byte, ea):
        '''Return the next address from the address `ea` that uses the specified `byte` value.'''
        return cls.nextbyte(byte, ea, 1)
    @utils.multicase(byte=internal.types.integer, ea=internal.types.integer, predicate=internal.types.callable)
    @classmethod
    def nextbyte(cls, byte, ea, predicate, **count):
        '''Return the next address from the address `ea` that uses the specified `byte` value and satisfies the given `predicate`.'''
        asize_t = idaapi.ea_pointer()
        _, uval = asize_t.assign(-1), asize_t.value() // 2
        next, counter, parameters = ~ea, max(1, count.get('count', 1)), [uval, byte, False] if idaapi.__version__ < 7.0 else [uval, byte, idaapi.BIN_SEARCH_FORWARD | idaapi.BIN_SEARCH_CASE]
        while counter > 0:
            next = idaapi.find_byte(ea + 1 if next == ea else ea, *parameters)
            if next == idaapi.BADADDR:
                raise E.AddressOutOfBoundsError(u"{:s}.nextbyte({:#0{:d}x}, {:#x}, {!s}{:s}): Refusing to seek past the bottom of the database ({:#x}). Stopped at address {:#x}.".format('.'.join([__name__, cls.__name__]), byte, 2 + 2, ea, predicate, ", {:s}".format(utils.string.kwargs(count)) if count else '', bottom(), ea))
            elif predicate(next):
                counter -= 1
            ea = next
        return ea
    @utils.multicase(byte=internal.types.integer, ea=internal.types.integer, count=internal.types.integer)
    @classmethod
    def nextbyte(cls, byte, ea, count):
        '''Return the next `count` addresses from the address `ea` that uses the specified `byte` value.'''
        asize_t = idaapi.ea_pointer()
        _, uval = asize_t.assign(-1), asize_t.value() // 2
        parameters = [uval, byte, False] if idaapi.__version__ < 7.0 else [uval, byte, idaapi.BIN_SEARCH_FORWARD | idaapi.BIN_SEARCH_CASE]
        next = ~ea
        for index in builtins.range(max(1, count)):
            next = idaapi.find_byte(ea + 1 if next == ea else ea, *parameters)
            if next == idaapi.BADADDR:
                raise E.AddressOutOfBoundsError(u"{:s}.nextbyte({:#0{:d}x}, {:#x}, {:d}): Refusing to seek past the bottom of the database ({:#x}). Stopped at address {:#x}.".format('.'.join([__name__, cls.__name__]), byte, 2 + 2, ea, count, bottom(), ea))
            ea = next
        return ea

    @utils.multicase()
    @classmethod
    def prevref(cls, **count):
        '''Return the previous address from the current one that has anything referencing it.'''
        return cls.prevref(ui.current.address(), count.pop('count', 1))
    @utils.multicase(predicate=internal.types.callable)
    @classmethod
    def prevref(cls, predicate, **count):
        '''Return the previous address from the current one that has anything referencing it and satisfies the provided `predicate`.'''
        return cls.prevref(ui.current.address(), predicate, **count)
    @utils.multicase(ea=internal.types.integer)
    @classmethod
    def prevref(cls, ea):
        '''Return the previous address from the address `ea` that has anything referencing it.'''
        return cls.prevref(ea, 1)
    @utils.multicase(ea=internal.types.integer, predicate=internal.types.callable)
    @classmethod
    def prevref(cls, ea, predicate, **count):
        '''Return the previous address from the address `ea` that has anything referencing it and satisfies the provided `predicate`.'''
        return cls.prevflag(functools.partial(operator.and_, idaapi.FF_REF), ea, predicate, **count)
    @utils.multicase(ea=internal.types.integer, count=internal.types.integer)
    @classmethod
    def prevref(cls, ea, count):
        '''Return the previous `count` addresses from the address `ea` that has anything referencing it.'''
        return cls.prevflag(functools.partial(operator.and_, idaapi.FF_REF), ea, count)

    @utils.multicase()
    @classmethod
    def nextref(cls, **count):
        '''Return the next address from the current one that has anything referencing it.'''
        return cls.nextref(ui.current.address(), count.pop('count', 1))
    @utils.multicase(predicate=internal.types.callable)
    @classmethod
    def nextref(cls, predicate, **count):
        '''Return the next address from the current one that has anything referencing it and satisfies the provided `predicate`.'''
        return cls.nextref(ui.current.address(), predicate, **count)
    @utils.multicase(ea=internal.types.integer)
    @classmethod
    def nextref(cls, ea):
        '''Return the next address from the address `ea` that has anything referencing it.'''
        return cls.nextref(ea, 1)
    @utils.multicase(ea=internal.types.integer, predicate=internal.types.callable)
    @classmethod
    def nextref(cls, ea, predicate, **count):
        '''Return the next address from the address `ea` that has anything referencing it and satisfies the provided `predicate`.'''
        return cls.nextflag(functools.partial(operator.and_, idaapi.FF_REF), ea, predicate, **count)
    @utils.multicase(ea=internal.types.integer, count=internal.types.integer)
    @classmethod
    def nextref(cls, ea, count):
        '''Return the next `count` addresses from the address `ea` that has anything referencing it.'''
        return cls.nextflag(functools.partial(operator.and_, idaapi.FF_REF), ea, count)

    @utils.multicase()
    @classmethod
    def prevdref(cls, **count):
        '''Return the previous address from the current one that has data referencing it.'''
        return cls.prevdref(ui.current.address(), count.pop('count', 1))
    @utils.multicase(predicate=internal.types.callable)
    @classmethod
    def prevdref(cls, predicate, **count):
        '''Return the previous address from the current one that has data referencing it and satisfies the provided `predicate`.'''
        return cls.prevdref(ui.current.address(), predicate, **count)
    @utils.multicase(ea=internal.types.integer)
    @classmethod
    def prevdref(cls, ea):
        '''Return the previous address from the address `ea` that has data referencing it.'''
        return cls.prevdref(ea, 1)
    @utils.multicase(ea=internal.types.integer, predicate=internal.types.callable)
    @classmethod
    def prevdref(cls, ea, predicate, **count):
        '''Return the previous address from the address `ea` that has data referencing it and satisfies the provided `predicate`.'''
        Fdref = utils.fcompose(xref.data_up, len, functools.partial(operator.lt, 0))
        F = utils.fcompose(utils.fmap(Fdref, predicate), builtins.all)
        return cls.prevref(ea, F, **count)
    @utils.multicase(ea=internal.types.integer, count=internal.types.integer)
    @classmethod
    def prevdref(cls, ea, count):
        '''Return the previous `count` addresses from the address `ea` that has data referencing it.'''
        Fdref = utils.fcompose(xref.data_up, len, functools.partial(operator.lt, 0))
        return cls.prevref(ea, Fdref, count=count)

    @utils.multicase()
    @classmethod
    def nextdref(cls, **count):
        '''Return the next address from the current one that has data referencing it.'''
        return cls.nextdref(ui.current.address(), count.pop('count', 1))
    @utils.multicase(predicate=internal.types.callable)
    @classmethod
    def nextdref(cls, predicate, **count):
        '''Return the next address from the current one that has data referencing it and satisfies the provided `predicate`.'''
        return cls.nextdref(ui.current.address(), predicate, **count)
    @utils.multicase(ea=internal.types.integer)
    @classmethod
    def nextdref(cls, ea):
        '''Return the next address from the address `ea` that has data referencing it.'''
        return cls.nextdref(ea, 1)
    @utils.multicase(ea=internal.types.integer, predicate=internal.types.callable)
    @classmethod
    def nextdref(cls, ea, predicate, **count):
        '''Return the next address from the address `ea` that has data referencing it and satisfies the provided `predicate`.'''
        Fdref = utils.fcompose(xref.data_up, len, functools.partial(operator.lt, 0))
        F = utils.fcompose(utils.fmap(Fdref, predicate), builtins.all)
        return cls.nextref(ea, F, **count)
    @utils.multicase(ea=internal.types.integer, count=internal.types.integer)
    @classmethod
    def nextdref(cls, ea, count):
        '''Return the next `count` addresses from the address `ea` that has data referencing it.'''
        Fdref = utils.fcompose(xref.data_up, len, functools.partial(operator.lt, 0))
        return cls.nextref(ea, Fdref, count=count)

    @utils.multicase()
    @classmethod
    def prevcref(cls, **count):
        '''Return the previous address from the current one that has code referencing it.'''
        return cls.prevcref(ui.current.address(), count.pop('count', 1))
    @utils.multicase(predicate=internal.types.callable)
    @classmethod
    def prevcref(cls, predicate, **count):
        '''Return the previous address from the current one that has code referencing it and satisfies the provided `predicate`.'''
        return cls.prevcref(ui.current.address(), predicate, **count)
    @utils.multicase(ea=internal.types.integer)
    @classmethod
    def prevcref(cls, ea):
        '''Return the previous address from the address `ea` that has code referencing it.'''
        return cls.prevcref(ea, 1)
    @utils.multicase(ea=internal.types.integer, predicate=internal.types.callable)
    @classmethod
    def prevcref(cls, ea, predicate, **count):
        '''Return the previous address from the address `ea` that has code referencing it and satisfies the provided `predicate`.'''
        Fcref = utils.fcompose(xref.code_up, len, functools.partial(operator.lt, 0))
        F = utils.fcompose(utils.fmap(Fcref, predicate), builtins.all)
        return cls.prevref(ea, F, **count)
    @utils.multicase(ea=internal.types.integer, count=internal.types.integer)
    @classmethod
    def prevcref(cls, ea, count):
        '''Return the previous `count` addresses from the address `ea` that has code referencing it.'''
        Fcref = utils.fcompose(xref.code_up, len, functools.partial(operator.lt, 0))
        return cls.prevref(ea, Fcref, count=count)

    @utils.multicase()
    @classmethod
    def nextcref(cls, **count):
        '''Return the next address from the current one that has code referencing it.'''
        return cls.nextcref(ui.current.address(), count.pop('count', 1))
    @utils.multicase(predicate=internal.types.callable)
    @classmethod
    def nextcref(cls, predicate, **count):
        '''Return the next address from the current one that has code referencing it and satisfies the provided `predicate`.'''
        return cls.nextcref(ui.current.address(), predicate, **count)
    @utils.multicase(ea=internal.types.integer)
    @classmethod
    def nextcref(cls, ea):
        '''Return the next address from the address `ea` that has code referencing it.'''
        return cls.nextcref(ea, 1)
    @utils.multicase(ea=internal.types.integer, predicate=internal.types.callable)
    @classmethod
    def nextcref(cls, ea, predicate, **count):
        '''Return the next address from the address `ea` that has code referencing it and satisfies the provided `predicate`.'''
        Fcref = utils.fcompose(xref.code_up, len, functools.partial(operator.lt, 0))
        F = utils.fcompose(utils.fmap(Fcref, predicate), builtins.all)
        return cls.nextref(ea, F, **count)
    @utils.multicase(ea=internal.types.integer, count=internal.types.integer)
    @classmethod
    def nextcref(cls, ea, count):
        '''Return the next `count` addresses from the address `ea` that has code referencing it.'''
        Fcref = utils.fcompose(xref.code_up, len, functools.partial(operator.lt, 0))
        return cls.nextref(ea, Fcref, count=count)

    @utils.multicase(reg=(internal.types.string, interface.register_t))
    @classmethod
    def prevreg(cls, reg, *regs, **modifiers):
        '''Return the previous address containing an instruction that uses `reg` or any one of the specified `regs`.'''
        return cls.prevreg(ui.current.address(), reg, *regs, **modifiers)
    @utils.multicase(predicate=internal.types.callable, reg=(internal.types.string, interface.register_t))
    @classmethod
    def prevreg(cls, predicate, reg, *regs, **modifiers):
        '''Return the previous address containing an instruction that uses `reg` or any one of the specified `regs` and satisfies the provided `predicate`.'''
        return cls.prevreg(ui.current.address(), predicate, reg, *regs, **modifiers)
    @utils.multicase(ea=internal.types.integer, reg=(internal.types.string, interface.register_t))
    @classmethod
    def prevreg(cls, ea, reg, *regs, **modifiers):
        '''Return the previous address from the address `ea` containing an instruction that uses `reg` or any one of the specified `regs`.'''
        return cls.prevreg(ea, modifiers.pop('predicate', utils.fconstant(True)), reg, *regs, **modifiers)
    @utils.multicase(ea=internal.types.integer, predicate=internal.types.callable, reg=(internal.types.string, interface.register_t))
    @classmethod
    def prevreg(cls, ea, predicate, reg, *regs, **modifiers):
        '''Return the previous address from the address `ea` containing an instruction that uses `reg` or any one of the specified `regs` and satisfies the provided `predicate`.'''
        regs = (reg,) + regs
        count = modifiers.get('count', 1)
        args = u', '.join(["{:x}".format(ea)] + ["{!r}".format(predicate)] + ["\"{:s}\"".format(utils.string.escape(str(reg), '"')) for reg in regs])
        args = args + (u", {:s}".format(utils.string.kwargs(modifiers)) if modifiers else '')

        # if we are within a function, then make sure we find a code type within
        # the chunk's bounds. thus we'll stop at the very top of the chunk.
        if interface.function.has(ea):
            start = interface.range.start(interface.function.chunk(interface.function.by_address(ea), ea))
            fwithin = utils.fcompose(utils.fmap(functools.partial(operator.le, start), type.code), builtins.all)

        # otherwise ensure that we find a code type that is not in the function,
        # which means that we'll stop at the very top of the database.
        else:
            fwithin = utils.fcompose(utils.fmap(utils.fcompose(interface.function.has, operator.not_), type.code), builtins.all)
            iterable = (item for item in interface.address.iterate(ea, idaapi.prev_not_tail) if not fwithin(ui.navigation.analyze(item)))
            res = builtins.next(iterable, None)
            start = top() if res is None else idaapi.get_item_end(res)

        # generate each helper using the regmatch class
        iterops = interface.regmatch.modifier(**modifiers)
        uses_register = interface.regmatch.use(regs)

        # define a predicate for checking whether an address uses the desired registers.
        Freg = lambda ea: fwithin(ea) and builtins.any(uses_register(ea, opnum) for opnum in iterops(ea))
        F = utils.fcompose(utils.fmap(Freg, predicate), builtins.all)

        # now grab all addresses where any of our registers match using the count.
        iterable = (item for item in interface.address.iterate(ea, idaapi.prev_not_tail) if item >= start and type.code(ui.navigation.analyze(item)) and F(item))
        items = [item for index, item in zip(builtins.range(count), iterable)]

        # if we didn't retrieve enough items, then we seeked past the top of the chunk.
        if count and len(items) < count:
            raise E.RegisterNotFoundError(u"{:s}.prevreg({:s}) : Unable to find register{:s} within the chunk {:#x}..{:#x}. Stopped at address {:#x}.".format('.'.join([__name__, cls.__name__]), args, '' if len(regs) == 1 else 's', start, ea - 1, items[-1] if items else ea))
        return items[-1] if items else ea

    @utils.multicase(reg=(internal.types.string, interface.register_t))
    @classmethod
    def nextreg(cls, reg, *regs, **modifiers):
        '''Return the next address containing an instruction that uses `reg` or any one of the specified `regs`.'''
        return cls.nextreg(ui.current.address(), reg, *regs, **modifiers)
    @utils.multicase(predicate=internal.types.callable, reg=(internal.types.string, interface.register_t))
    @classmethod
    def nextreg(cls, predicate, reg, *regs, **modifiers):
        '''Return the next address containing an instruction uses `reg` or any one of the specified `regs` and satisfies the provided `predicate`.'''
        return cls.nextreg(ui.current.address(), predicate, reg, *regs, **modifiers)
    @utils.multicase(ea=internal.types.integer, reg=(internal.types.string, interface.register_t))
    @classmethod
    def nextreg(cls, ea, reg, *regs, **modifiers):
        '''Return the next address from the address `ea` containing an instruction that uses `reg` or any one of the specified `regs`.'''
        return cls.nextreg(ea, modifiers.pop('predicate', utils.fconstant(True)), reg, *regs, **modifiers)
    @utils.multicase(ea=internal.types.integer, predicate=internal.types.callable, reg=(internal.types.string, interface.register_t))
    @classmethod
    def nextreg(cls, ea, predicate, reg, *regs, **modifiers):
        '''Return the next address from the address `ea` containing an instruction that uses `reg` or any one of the specified `regs` and satisfies the provided `predicate`.'''
        regs = (reg,) + regs
        count = modifiers.get('count', 1)
        args = u', '.join(["{:x}".format(ea)] + ["{!r}".format(predicate)] + ["\"{:s}\"".format(utils.string.escape(str(reg), '"')) for reg in regs])
        args = args + (u", {:s}".format(utils.string.kwargs(modifiers)) if modifiers else '')

        # if we are within a function, then make sure we find a code type within
        # the chunk's bounds. thus we'll stop at the very end of the chunk.
        if interface.function.has(ea):
            end = interface.range.end(interface.function.chunk(interface.function.by_address(ea), ea))
            fwithin = utils.fcompose(utils.fmap(functools.partial(operator.gt, end), type.code), builtins.all)

        # otherwise ensure that we find a code type that is not in the function,
        # which means that we'll stop at the very bottom of the database.
        else:
            fwithin = utils.fcompose(utils.fmap(utils.fcompose(interface.function.has, operator.not_), type.code), builtins.all)
            iterable = (item for item in interface.address.iterate(ea, idaapi.next_not_tail) if not fwithin(ui.navigation.analyze(item)))
            res = builtins.next(iterable, None)
            end = bottom() if res is None else idaapi.get_item_head(res)

        # generate each helper using the regmatch class
        iterops = interface.regmatch.modifier(**modifiers)
        uses_register = interface.regmatch.use(regs)

        # define a predicate for checking whether an address uses the desired registers.
        Freg = lambda ea: fwithin(ea) and builtins.any(uses_register(ea, opnum) for opnum in iterops(ea))
        F = utils.fcompose(utils.fmap(Freg, predicate), builtins.all)

        # now grab all addresses where any of our registers match using the count.
        iterable = (item for item in interface.address.iterate(ea, idaapi.next_not_tail) if item < end and type.code(ui.navigation.analyze(item)) and F(item))
        items = [item for index, item in zip(builtins.range(count), iterable)]

        # if we didn't retrieve enough items, then we seeked past the top of the chunk.
        if count and len(items) < count:
            raise E.RegisterNotFoundError(u"{:s}.nextreg({:s}) : Unable to find register{:s} within the chunk {:#x}..{:#x}. Stopped at address {:#x}.".format('.'.join([__name__, cls.__name__]), args, '' if len(regs) == 1 else 's', ea, end - 1, items[-1] if items else ea))
        return items[-1] if items else ea

    # FIXME: these two functions, prevstack and nextstack, should be deprecated as they're really not
    #        useful for anything and their performance sucks. the only reason why they're not deprecated
    #        is because they're used in tools.general.makecall...which should also be considered dead.
    @utils.multicase(delta=internal.types.integer)
    @classmethod
    def prevstack(cls, delta):
        '''Return the previous instruction from the current one that is past the specified sp `delta`.'''
        return cls.prevstack(ui.current.address(), delta)
    @utils.multicase(ea=internal.types.integer, delta=internal.types.integer)
    @classmethod
    def prevstack(cls, ea, delta):
        '''Return the previous instruction from the address `ea` that is past the specified sp `delta`.'''

        # FIXME: it'd be much better to keep track of this with a global class that wraps the logger
        if getattr(cls, '__prevstack_warning_count__', 0) == 0:
            logging.warning(u"{:s}.prevstack({:#x}, {:#x}) : This function will be deprecated in the near future. Please use `{:s}` or Hex-Rays to locate stack points.".format('.'.join([__name__, cls.__name__]), ea, delta, utils.pycompat.fullname(function.chunk.points)))
            cls.__prevstack_warning_count__ = getattr(cls, '__prevstack_warning_count__', 0) + 1

        # Get all the stack changes within the current function chunk, and the
        # current sp. This way we can bisect to find our starting point and
        # traverse backwards from there.
        points = [(item, sp) for item, sp in function.chunk.points(ea)]
        addresses = [item for item, _ in points]

        # Now we'll bisect our list of items in order to slice the points out
        # that are completely irrelevant, and reverse the list so that
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
        # so that we can raise an exception for the user.
        else:
            fn, end = function.address(ea), filtered[-1] if filtered else ea
        raise E.AddressOutOfBoundsError(u"{:s}.prevstack({:#x}, {:+#x}) : Unable to locate instruction matching contraints due to encountering the first stack point ({:#x}) of the function {:#x}.".format('.'.join([__name__, cls.__name__]), ea, delta, end, fn))

    # XXX: this function needs to be completely removed... it's not even remotely
    #      useful and only exists as the inverse of prevstack.
    @utils.multicase(delta=internal.types.integer)
    @classmethod
    def nextstack(cls, delta):
        '''Return the next instruction from the current one that is past the sp `delta`.'''
        return cls.nextstack(ui.current.address(), delta)
    @utils.multicase(ea=internal.types.integer, delta=internal.types.integer)
    @classmethod
    def nextstack(cls, ea, delta):
        '''Return the next instruction from the address `ea` that is past the sp `delta`.'''

        # FIXME: it'd be much better to keep track of this with a global class that wraps the logger
        if getattr(cls, '__nextstack_warning_count__', 0) == 0:
            logging.warning(u"{:s}.nextstack({:#x}, {:#x}) : This function will be deprecated in the near future. Please use `{:s}` or Hex-Rays to locate stack points.".format('.'.join([__name__, cls.__name__]), ea, delta, utils.pycompat.fullname(function.chunk.points)))
            cls.__nextstack_warning_count__ = getattr(cls, '__nextstack_warning_count__', 0) + 1

        # Get all the stack changes within the current function chunk, and the
        # current sp. This way we can bisect to find out where to start from
        # and continue to walk forwards from there to find our match.
        points = [(item, sp) for item, sp in function.chunk.points(ea)]
        addresses = [item for item, _ in points]

        # Now we'll bisect our list of items in order to select only the
        # points that are relevant. This way we can just walk the list
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
            fn, end = function.address(ea), filtered[-1] if filtered else ea
        raise E.AddressOutOfBoundsError(u"{:s}.nextstack({:#x}, {:+#x}) : Unable to locate instruction matching contraints due to encountering the last stack point ({:#x}) of the function {:#x}.".format('.'.join([__name__, cls.__name__]), ea, delta, end, fn))

    @utils.multicase()
    @classmethod
    def prevcall(cls, **count):
        '''Return the previous call instruction from the current address.'''
        return cls.prevcall(ui.current.address(), count.pop('count', 1))
    @utils.multicase(predicate=internal.types.callable)
    @classmethod
    def prevcall(cls, predicate, **count):
        '''Return the previous call instruction from the current address that satisfies the provided `predicate`.'''
        return cls.prevcall(ui.current.address(), predicate, **count)
    @utils.multicase(ea=internal.types.integer)
    @classmethod
    def prevcall(cls, ea):
        '''Return the previous call instruction from the address `ea`.'''
        return cls.prevcall(ea, 1)
    @utils.multicase(ea=internal.types.integer, predicate=internal.types.callable)
    @classmethod
    def prevcall(cls, ea, predicate, **count):
        '''Return the previous call instruction from the address `ea` that satisfies the provided `predicate`.'''
        F = utils.fcompose(utils.fmap(interface.instruction.is_call, predicate), builtins.all)
        return cls.prevF(ea, F, count.pop('count', 1))
    @utils.multicase(ea=internal.types.integer, count=internal.types.integer)
    @classmethod
    def prevcall(cls, ea, count):
        '''Return the previous `count` call instructions from the address `ea`.'''
        return cls.prevF(ea, interface.instruction.is_call, count)

    @utils.multicase()
    @classmethod
    def nextcall(cls, **count):
        '''Return the next call instruction from the current address.'''
        return cls.nextcall(ui.current.address(), count.pop('count', 1))
    @utils.multicase(predicate=internal.types.callable)
    @classmethod
    def nextcall(cls, predicate, **count):
        '''Return the next call instruction from the current address that satisfies the provided `predicate`.'''
        return cls.nextcall(ui.current.address(), predicate, **count)
    @utils.multicase(ea=internal.types.integer)
    @classmethod
    def nextcall(cls, ea):
        '''Return the next call instruction from the address `ea`.'''
        return cls.nextcall(ea, 1)
    @utils.multicase(ea=internal.types.integer, predicate=internal.types.callable)
    @classmethod
    def nextcall(cls, ea, predicate, **count):
        '''Return the next call instruction from the address `ea` that satisfies the provided `predicate`.'''
        F = utils.fcompose(utils.fmap(interface.instruction.is_call, predicate), builtins.all)
        return cls.nextF(ea, F, count.pop('count', 1))
    @utils.multicase(ea=internal.types.integer, count=internal.types.integer)
    @classmethod
    def nextcall(cls, ea, count):
        '''Return the next `count` call instructions from the address `ea`.'''
        return cls.nextF(ea, interface.instruction.is_call, count)

    @utils.multicase()
    @classmethod
    def prevbranch(cls, **count):
        '''Return the previous branch instruction from the current one.'''
        return cls.prevbranch(ui.current.address(), count.pop('count', 1))
    @utils.multicase(predicate=internal.types.callable)
    @classmethod
    def prevbranch(cls, predicate, **count):
        '''Return the previous branch instruction from the current one that satisfies the provided `predicate`.'''
        return cls.prevbranch(ui.current.address(), predicate, **count)
    @utils.multicase(ea=internal.types.integer)
    @classmethod
    def prevbranch(cls, ea):
        '''Return the previous branch instruction from the address `ea`.'''
        return cls.prevbranch(ea, 1)
    @utils.multicase(ea=internal.types.integer, predicate=internal.types.callable)
    @classmethod
    def prevbranch(cls, ea, predicate, **count):
        '''Return the previous branch instruction from the address `ea` that satisfies the provided `predicate`.'''
        F = utils.fcompose(utils.fmap(interface.instruction.is_branch, predicate), builtins.all)
        return cls.prevF(ea, F, count.pop('count', 1))
    @utils.multicase(ea=internal.types.integer, count=internal.types.integer)
    @classmethod
    def prevbranch(cls, ea, count):
        '''Return the previous `count` branch instructions from the address `ea`.'''
        return cls.prevF(ea, interface.instruction.is_branch, count)

    @utils.multicase()
    @classmethod
    def nextbranch(cls, **count):
        '''Return the next branch instruction from the current one.'''
        return cls.nextbranch(ui.current.address(), count.pop('count', 1))
    @utils.multicase(predicate=internal.types.callable)
    @classmethod
    def nextbranch(cls, predicate, **count):
        '''Return the next branch instruction that satisfies the provided `predicate`.'''
        return cls.nextbranch(ui.current.address(), predicate, **count)
    @utils.multicase(ea=internal.types.integer)
    @classmethod
    def nextbranch(cls, ea):
        '''Return the next branch instruction from the address `ea`.'''
        return cls.nextbranch(ea, 1)
    @utils.multicase(ea=internal.types.integer, predicate=internal.types.callable)
    @classmethod
    def nextbranch(cls, ea, predicate, **count):
        '''Return the next branch instruction from the address `ea` that satisfies the provided `predicate`.'''
        F = utils.fcompose(utils.fmap(interface.instruction.is_branch, predicate), builtins.all)
        return cls.nextF(ea, F, count.pop('count', 1))
    @utils.multicase(ea=internal.types.integer, count=internal.types.integer)
    @classmethod
    def nextbranch(cls, ea, count):
        '''Return the next `count` branch instructions from the address `ea`.'''
        return cls.nextF(ea, interface.instruction.is_branch, count)

    @utils.multicase(mnemonics=(internal.types.string, internal.types.unordered))
    @classmethod
    def prevmnemonic(cls, mnemonics):
        '''Return the address of the previous instruction from the current address that uses any of the specified `mnemonics`.'''
        return cls.prevmnemonic(mnemonics, ui.current.address(), 1)
    @utils.multicase(ea=internal.types.integer, mnemonics=(internal.types.string, internal.types.unordered))
    @classmethod
    def prevmnemonic(cls, mnemonics, ea):
        '''Return the address of the previous instruction from the address `ea` that uses any of the specified `mnemonics`.'''
        return cls.prevmnemonic(mnemonics, ea, 1)
    @utils.multicase(ea=internal.types.integer, mnemonics=(internal.types.string, internal.types.unordered), predicate=internal.types.callable)
    @classmethod
    def prevmnemonic(cls, mnemonics, ea, predicate, **count):
        '''Return the address of the previous instruction from the address `ea` that uses any of the specified `mnemonics` and satisfies the provided `predicate`.'''
        items = {mnemonics} if isinstance(mnemonics, internal.types.string) else {item for item in mnemonics}
        Fuses_mnemonics = utils.fcompose(interface.instruction.mnemonic, utils.fpartial(operator.contains, items))
        F = utils.fcompose(utils.fmap(Fuses_mnemonics, predicate), builtins.all)
        return cls.prevF(ea, F, count.pop('count', 1))
    @utils.multicase(ea=internal.types.integer, mnemonics=(internal.types.string, internal.types.unordered), count=internal.types.integer)
    @classmethod
    def prevmnemonic(cls, mnemonics, ea, count):
        '''Return the address of the previous `count` instructions from the address `ea` that uses any of the specified `mnemonics`.'''
        items = {mnemonics} if isinstance(mnemonics, internal.types.string) else {item for item in mnemonics}
        Fuses_mnemonics = utils.fcompose(interface.instruction.mnemonic, utils.fpartial(operator.contains, items))
        return cls.prevF(ea, Fuses_mnemonics, count)

    @utils.multicase(mnemonics=(internal.types.string, internal.types.unordered))
    @classmethod
    def nextmnemonic(cls, mnemonics):
        '''Return the address of the next instruction from the current address that uses any of the specified `mnemonics`.'''
        return cls.nextmnemonic(mnemonics, ui.current.address(), 1)
    @utils.multicase(ea=internal.types.integer, mnemonics=(internal.types.string, internal.types.unordered))
    @classmethod
    def nextmnemonic(cls, mnemonics, ea):
        '''Return the address of the next instruction from the address `ea` that uses any of the specified `mnemonics`.'''
        return cls.nextmnemonic(mnemonics, ea, 1)
    @utils.multicase(ea=internal.types.integer, mnemonics=(internal.types.string, internal.types.unordered), predicate=internal.types.callable)
    @classmethod
    def nextmnemonic(cls, mnemonics, ea, predicate, **count):
        '''Return the address of the next instruction from the address `ea` that uses any of the specified `mnemonics` and satisfies the provided `predicate`.'''
        items = {mnemonics} if isinstance(mnemonics, internal.types.string) else {item for item in mnemonics}
        Fuses_mnemonics = utils.fcompose(interface.instruction.mnemonic, utils.fpartial(operator.contains, items))
        F = utils.fcompose(utils.fmap(Fuses_mnemonics, predicate), builtins.all)
        return cls.nextF(ea, F, count.pop('count', 1))
    @utils.multicase(ea=internal.types.integer, mnemonics=(internal.types.string, internal.types.unordered), count=internal.types.integer)
    @classmethod
    def nextmnemonic(cls, mnemonics, ea, count):
        '''Return the address of the next `count` instructions from the address `ea` that uses any of the specified `mnemonics`.'''
        items = {mnemonics} if isinstance(mnemonics, internal.types.string) else {item for item in mnemonics}
        Fuses_mnemonics = utils.fcompose(interface.instruction.mnemonic, utils.fpartial(operator.contains, items))
        return cls.nextF(ea, Fuses_mnemonics, count)

    @utils.multicase()
    @classmethod
    def prevlabel(cls, **count):
        '''Return the address of the previous label from the current address.'''
        return cls.prevlabel(ui.current.address(), count.pop('count', 1))
    @utils.multicase(predicate=internal.types.callable)
    @classmethod
    def prevlabel(cls, predicate, **count):
        '''Return the address of the previous label from the current address that satisfies the provided `predicate`.'''
        return cls.prevlabel(ui.current.address(), predicate, **count)
    @utils.multicase(ea=internal.types.integer)
    @classmethod
    def prevlabel(cls, ea):
        '''Return the address of the previous label from the address `ea`.'''
        return cls.prevlabel(ea, 1)
    @utils.multicase(ea=internal.types.integer, predicate=internal.types.callable)
    @classmethod
    def prevlabel(cls, ea, predicate, **count):
        '''Return the address of the previous label from the address `ea` that satisfies the provided `predicate`.'''
        return cls.prevflag(functools.partial(operator.and_, idaapi.FF_LABL|idaapi.FF_NAME), ea, predicate, **count)
    @utils.multicase(ea=internal.types.integer, count=internal.types.integer)
    @classmethod
    def prevlabel(cls, ea, count):
        '''Return the address of the previous `count` labels from the address `ea`.'''
        return cls.prevflag(functools.partial(operator.and_, idaapi.FF_LABL|idaapi.FF_NAME), ea, count)

    @utils.multicase()
    @classmethod
    def nextlabel(cls, **count):
        '''Return the address of the next label from the current address.'''
        return cls.nextlabel(ui.current.address(), count.pop('count', 1))
    @utils.multicase(predicate=internal.types.callable)
    @classmethod
    def nextlabel(cls, predicate, **count):
        '''Return the address of the next label from the current address that satisfies the provided `predicate`.'''
        return cls.nextlabel(ui.current.address(), predicate, **count)
    @utils.multicase(ea=internal.types.integer)
    @classmethod
    def nextlabel(cls, ea):
        '''Return the address of the next label from the address `ea`.'''
        return cls.nextlabel(ea, 1)
    @utils.multicase(ea=internal.types.integer, predicate=internal.types.callable)
    @classmethod
    def nextlabel(cls, ea, predicate, **count):
        '''Return the address of the next label from the address `ea` that satisfies the provided `predicate`.'''
        return cls.nextflag(functools.partial(operator.and_, idaapi.FF_LABL|idaapi.FF_NAME), ea, predicate, **count)
    @utils.multicase(ea=internal.types.integer, count=internal.types.integer)
    @classmethod
    def nextlabel(cls, ea, count):
        '''Return the address of the next `count` labels from the address `ea`.'''
        return cls.nextflag(functools.partial(operator.and_, idaapi.FF_LABL|idaapi.FF_NAME), ea, count)

    @utils.multicase()
    @classmethod
    def prevcomment(cls, **repeatable):
        '''Return the previous address from the current one that has any type of comment.'''
        return cls.prevcomment(ui.current.address(), repeatable.pop('count', 1), **repeatable)
    @utils.multicase(predicate=internal.types.callable)
    @classmethod
    def prevcomment(cls, predicate, **repeatable):
        '''Return the previous address from the current one that has any type of comment and satisfies the provided `predicate`.'''
        return cls.prevcomment(ui.current.address(), predicate, **repeatable)
    @utils.multicase(ea=internal.types.integer)
    @classmethod
    def prevcomment(cls, ea, **repeatable):
        '''Return the previous address from the address `ea` that has any type of comment.'''
        return cls.prevcomment(ea, repeatable.pop('count', 1), **repeatable)
    @utils.multicase(ea=internal.types.integer, predicate=internal.types.callable)
    @classmethod
    def prevcomment(cls, ea, predicate, **repeatable):
        """Return the previous address from the address `ea` that has any type of comment and satisfies the provided `predicate`.

        If the bool `repeatable` is defined, then use it to determine whether to only track repeatable or non-repeatable comments.
        """
        if 'repeatable' in repeatable:
            Fcheck_comment = utils.fcompose(utils.frpartial(idaapi.get_cmt, not repeatable.pop('repeatable')), utils.fpartial(operator.is_, None))
            F = utils.fcompose(utils.fmap(Fcheck_comment, predicate), builtins.all)
        else:
            F = predicate
        return cls.prevflag(functools.partial(operator.and_, idaapi.FF_COMM), ea, F, **repeatable)
    @utils.multicase(ea=internal.types.integer, count=internal.types.integer)
    @classmethod
    def prevcomment(cls, ea, count, **repeatable):
        """Return the previous `count` addresses from the address `ea` that has any type of comment.

        If the bool `repeatable` is defined, then use it to determine whether to only track repeatable or non-repeatable comments.
        """
        if 'repeatable' in repeatable:
            Fcheck_comment = utils.fcompose(utils.frpartial(idaapi.get_cmt, not repeatable.pop('repeatable')), utils.fpartial(operator.is_, None))
            return cls.prevflag(functools.partial(operator.and_, idaapi.FF_COMM), ea, Fcheck_comment, **repeatable)
        return cls.prevflag(functools.partial(operator.and_, idaapi.FF_COMM), ea, count, **repeatable)

    @utils.multicase()
    @classmethod
    def nextcomment(cls, **repeatable):
        '''Return the next address from the current one that has any type of comment.'''
        return cls.nextcomment(ui.current.address(), repeatable.pop('count', 1), **repeatable)
    @utils.multicase(predicate=internal.types.callable)
    @classmethod
    def nextcomment(cls, predicate, **repeatable):
        '''Return the next address from the current one that has any type of comment and satisfies the provided `predicate`.'''
        return cls.nextcomment(ui.current.address(), predicate, **repeatable)
    @utils.multicase(ea=internal.types.integer)
    @classmethod
    def nextcomment(cls, ea, **repeatable):
        '''Return the next address from the address `ea` that has any type of comment.'''
        return cls.nextcomment(ea, repeatable.pop('count', 1), **repeatable)
    @utils.multicase(ea=internal.types.integer, predicate=internal.types.callable)
    @classmethod
    def nextcomment(cls, ea, predicate, **repeatable):
        """Return the next address from the address `ea` that has any type of comment and satisfies the provided `predicate`.

        If the bool `repeatable` is defined, then use it to determine whether to only track repeatable or non-repeatable comments.
        """
        if 'repeatable' in repeatable:
            Fcheck_comment = utils.fcompose(utils.frpartial(idaapi.get_cmt, not repeatable.pop('repeatable')), utils.fpartial(operator.is_, None))
            F = utils.fcompose(utils.fmap(Fcheck_comment, predicate), builtins.all)
        else:
            F = predicate
        return cls.nextflag(functools.partial(operator.and_, idaapi.FF_COMM), ea, F, **repeatable)
    @utils.multicase(ea=internal.types.integer, count=internal.types.integer)
    @classmethod
    def nextcomment(cls, ea, count, **repeatable):
        """Return the next `count` addresses from the address `ea` that has any type of comment.

        If the bool `repeatable` is defined, then use it to determine whether to only track repeatable or non-repeatable comments.
        """
        if 'repeatable' in repeatable:
            Fcheck_comment = utils.fcompose(utils.frpartial(idaapi.get_cmt, not repeatable.pop('repeatable')), utils.fpartial(operator.is_, None))
            return cls.nextflag(functools.partial(operator.and_, idaapi.FF_COMM), ea, Fcheck_comment, **repeatable)
        return cls.prevflag(functools.partial(operator.and_, idaapi.FF_COMM), ea, count, **repeatable)

    # FIXME: We should add the Or= or And= tests to this or we should allow specifying a set of tags.
    @utils.multicase()
    @classmethod
    @utils.string.decorate_arguments('tagname', 'tag', 'name')
    def prevtag(cls, **tagname):
        '''Return the previous address that contains a tag using the specified `tagname`.'''
        return cls.prevtag(ui.current.address(), tagname.pop('count', 1), **tagname)
    @utils.multicase(predicate=internal.types.callable)
    @classmethod
    @utils.string.decorate_arguments('tagname', 'tag', 'name')
    def prevtag(cls, predicate, **tagname):
        '''Return the previous address that contains a tag using the specified `tagname` and satisfies the provided `predicate`.'''
        return cls.prevtag(ui.current.address(), predicate, **tagname)
    @utils.multicase(ea=internal.types.integer)
    @classmethod
    @utils.string.decorate_arguments('tagname', 'tag', 'name')
    def prevtag(cls, ea, **tagname):
        '''Return the previous address from `ea` that contains a tag using the specified `tagname`.'''
        return cls.prevtag(ea, tagname.pop('count', 1), **tagname)
    @utils.multicase(ea=internal.types.integer, predicate=internal.types.callable)
    @classmethod
    @utils.string.decorate_arguments('tagname', 'tag', 'name')
    def prevtag(cls, ea, predicate, **tagname):
        '''Return the previous address from `ea` that contains a tag using the specified `tagname` and satisfies the provided `predicate`.'''
        tags = builtins.next((tagname.pop(kwd) for kwd in ['tagname', 'tag', 'name'] if kwd in tagname), None)
        if tags is None:
            return cls.prevflag(functools.partial(operator.and_, idaapi.FF_COMM), ea, **tagname)
        Ftests = [utils.frpartial(operator.contains, tags)] if isinstance(tags, internal.types.string) else [builtins.set, functools.partial(operator.and_, {item for item in tags})]
        return cls.prevflag(functools.partial(operator.and_, idaapi.FF_COMM), ea, utils.fcompose(internal.tags.address.get, *Ftests), **tagname)
    @utils.multicase(ea=internal.types.integer, count=internal.types.integer)
    @classmethod
    @utils.string.decorate_arguments('tagname', 'tag', 'name')
    def prevtag(cls, ea, count, **tagname):
        '''Return the previous `count` addresses from `ea` that contains a tag using the specified `tagname`.'''
        tags = builtins.next((tagname.pop(kwd) for kwd in ['tagname', 'tag', 'name'] if kwd in tagname), None)
        if tags is None:
            return cls.prevflag(functools.partial(operator.and_, idaapi.FF_COMM), ea, count, **tagname)
        Ftests = [utils.frpartial(operator.contains, tags)] if isinstance(tags, internal.types.string) else [builtins.set, functools.partial(operator.and_, {item for item in tags})]
        return cls.prevflag(functools.partial(operator.and_, idaapi.FF_COMM), ea, utils.fcompose(internal.tags.address.get, *Ftests), **tagname)

    # FIXME: We should add the Or= or And= tests to this or we should allow specifying a set of tags.
    @utils.multicase()
    @classmethod
    @utils.string.decorate_arguments('tagname', 'tag', 'name')
    def nexttag(cls, **tagname):
        '''Return the next address that contains a tag using the specified `tagname`.'''
        return cls.nexttag(ui.current.address(), tagname.pop('count', 1), **tagname)
    @utils.multicase(predicate=internal.types.callable)
    @classmethod
    @utils.string.decorate_arguments('tagname', 'tag', 'name')
    def nexttag(cls, predicate, **tagname):
        '''Return the next address that contains a tag using the specified `tagname` and satisfies the provided `predicate`.'''
        return cls.nexttag(ui.current.address(), predicate, **tagname)
    @utils.multicase(ea=internal.types.integer)
    @classmethod
    @utils.string.decorate_arguments('tagname', 'tag', 'name')
    def nexttag(cls, ea, **tagname):
        '''Return the next address from `ea` that contains a tag using the specified `tagname`.'''
        return cls.nexttag(ea, tagname.pop('count', 1), **tagname)
    @utils.multicase(ea=internal.types.integer, predicate=internal.types.callable)
    @classmethod
    @utils.string.decorate_arguments('tagname', 'tag', 'name')
    def nexttag(cls, ea, predicate, **tagname):
        '''Return the next address from `ea` that contains a tag using the specified `tagname` and satisfies the provided `predicate`.'''
        tags = builtins.next((tagname.pop(kwd) for kwd in ['tagname', 'tag', 'name'] if kwd in tagname), None)
        if tags is None:
            return cls.nextflag(functools.partial(operator.and_, idaapi.FF_COMM), ea, **tagname)
        Ftests = [utils.frpartial(operator.contains, tags)] if isinstance(tags, internal.types.string) else [builtins.set, functools.partial(operator.and_, {item for item in tags})]
        return cls.nextflag(functools.partial(operator.and_, idaapi.FF_COMM), ea, utils.fcompose(internal.tags.address.get, *Ftests), **tagname)
    @utils.multicase(ea=internal.types.integer, count=internal.types.integer)
    @classmethod
    @utils.string.decorate_arguments('tagname', 'tag', 'name')
    def nexttag(cls, ea, count, **tagname):
        '''Return the next `count` addresses from `ea` that contains a tag using the specified `tagname`.'''
        tags = builtins.next((tagname.pop(kwd) for kwd in ['tagname', 'tag', 'name'] if kwd in tagname), None)
        if tags is None:
            return cls.nextflag(functools.partial(operator.and_, idaapi.FF_COMM), ea, count, **tagname)
        Ftests = [utils.frpartial(operator.contains, tags)] if isinstance(tags, internal.types.string) else [builtins.set, functools.partial(operator.and_, {item for item in tags})]
        return cls.nextflag(functools.partial(operator.and_, idaapi.FF_COMM), ea, utils.fcompose(internal.tags.address.get, *Ftests), **tagname)

    @utils.multicase()
    @classmethod
    def prevfunction(cls, **count):
        '''Return the previous address from the current address that is within a function.'''
        return cls.prevfunction(ui.current.address(), count.pop('count', 1))
    @utils.multicase(ea=internal.types.integer)
    @classmethod
    def prevfunction(cls, ea):
        '''Return the previous address from the address `ea` that is within a function.'''
        return cls.prevfunction(ea, 1)
    @utils.multicase(ea=internal.types.integer, predicate=internal.types.callable)
    @classmethod
    def prevfunction(cls, ea, predicate, **count):
        '''Return the previous address from the address `ea` that is within a function and satisfies the provided `predicate`.'''
        counter = max(1, count.get('count', 1))
        while counter > 0:
            fn = idaapi.get_prev_fchunk(ea)
            if not fn:
                raise E.AddressOutOfBoundsError(u"{:s}.prevfunction({:#x}, {!s}{:s}): Refusing to seek past the top of the database ({:#x}). Stopped at address {:#x}.".format('.'.join([__name__, cls.__name__]), ea, predicate, ", {:s}".format(utils.string.kwargs(count)) if count else '', top(), ea))
            else:
                next = interface.range.stop(fn) - 1
            if predicate(next):
                count -= 1
            ea = next
        return ea
    @utils.multicase(ea=internal.types.integer, count=internal.types.integer)
    @classmethod
    def prevfunction(cls, ea, count):
        '''Return the previous `count` addresses from the address `ea` that is within a function.'''
        for index in builtins.range(max(1, count)):
            fn = idaapi.get_prev_fchunk(ea)
            if not fn:
                raise E.AddressOutOfBoundsError(u"{:s}.prevfunction({:#x}, {:d}): Refusing to seek past the top of the database ({:#x}). Stopped at address {:#x}.".format('.'.join([__name__, cls.__name__]), ea, count, top(), ea))
            ea = interface.range.stop(fn) - 1
        return ea

    @utils.multicase()
    @classmethod
    def nextfunction(cls, **count):
        '''Return the next address from the current address that is within a function.'''
        return cls.nextfunction(ui.current.address(), count.pop('count', 1))
    @utils.multicase(ea=internal.types.integer)
    @classmethod
    def nextfunction(cls, ea):
        '''Return the next address from the address `ea` that is within a function.'''
        return cls.nextfunction(ea, 1)
    @utils.multicase(ea=internal.types.integer, predicate=internal.types.callable)
    @classmethod
    def nextfunction(cls, ea, predicate, **count):
        '''Return the next address from the address `ea` that is within a function and satisfies the provided `predicate`.'''
        next, counter = ~ea, max(1, count.get('count', 1))
        while counter > 0:
            fn = idaapi.get_next_fchunk(ea + 1 if next == ea else ea)
            if not fn:
                raise E.AddressOutOfBoundsError(u"{:s}.nextfunction({:#x}, {!s}{:s}): Refusing to seek past the bottom of the database ({:#x}). Stopped at address {:#x}.".format('.'.join([__name__, cls.__name__]), ea, predicate, ", {:s}".format(utils.string.kwargs(count)) if count else '', bottom(), ea))
            else:
                next = interface.range.start(fn)
            if predicate(next):
                counter -= 1
            ea = next
        return ea
    @utils.multicase(ea=internal.types.integer, count=internal.types.integer)
    @classmethod
    def nextfunction(cls, ea, count):
        '''Return the next `count` addresses from the address `ea` that is within a function.'''
        next = ~ea
        for index in builtins.range(max(1, count)):
            fn = idaapi.get_next_fchunk(ea + 1 if next == ea else ea)
            if not fn:
                raise E.AddressOutOfBoundsError(u"{:s}.nextfunction({:#x}, {:d}): Refusing to seek past the bottom of the database ({:#x}). Stopped at address {:#x}.".format('.'.join([__name__, cls.__name__]), ea, count, bottom(), ea))
            ea = next = interface.range.start(fn)
        return ea
    prevfunc, nextfunc = utils.alias(prevfunction, 'address'), utils.alias(nextfunction, 'address')

    # address translations
    @classmethod
    def by_offset(cls, offset):
        '''Return the specified `offset` translated to an address in the database.'''
        return information.baseaddress() + offset
    byoffset = utils.alias(by_offset, 'address')

    @utils.multicase()
    @classmethod
    def offset(cls):
        '''Return the current address translated to an offset relative to the base address of the database.'''
        return cls.offset(ui.current.address())
    @utils.multicase(ea=internal.types.integer)
    @classmethod
    def offset(cls, ea):
        '''Return the address `ea` translated to an offset relative to the base address of the database.'''
        return interface.address.offset(interface.address.inside(ea))
    getoffset = utils.alias(offset, 'address')

    @utils.multicase()
    @classmethod
    def fileoffset(cls):
        '''Return the file offset in the input file for the current address.'''
        return cls.fileoffset(ui.current.address())
    @utils.multicase(ea=internal.types.integer)
    @classmethod
    def fileoffset(cls, ea):
        '''Return the file offset in the input file for the address `ea`.'''
        return idaapi.get_fileregion_offset(ea)

    @utils.multicase(offset=internal.types.integer)
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
        > print( database.type.initialized(ea) )
        > print( database.type.data(ea) )
        > length = database.t.array.length(ea)
        > st = database.t.structure(ea)

    """

    @utils.multicase()
    def __new__(cls):
        '''Return the type information for the current address as an ``idaapi.tinfo_t``.'''
        return cls(ui.current.address())
    @utils.multicase(ea=internal.types.integer)
    def __new__(cls, ea):
        '''Return the type information for the address `ea` as an ``idaapi.tinfo_t``.'''
        return interface.address.typeinfo(ea)
    @utils.multicase(none=internal.types.none)
    def __new__(cls, none):
        '''Remove the type information from the current address.'''
        return cls(ui.current.address(), None)
    @utils.multicase(info=(internal.types.string, idaapi.tinfo_t))
    def __new__(cls, info, **guessed):
        '''Apply the type information in `info` to the current address.'''
        return cls(ui.current.address(), info, **guessed)
    @utils.multicase(ea=internal.types.integer, info=idaapi.tinfo_t)
    def __new__(cls, ea, info, **guessed):
        """Apply the ``idaapi.tinfo_t`` in `info` to the address `ea`.

        If `guess` is true, then apply the type information as a guess.
        If `force` is true, then apply the type as-is regardless of its location.
        """
        info_s = "{!s}".format(info)

        # Check if we're pointing directly at a function or a runtime-linked one.
        try:
            rt, ea = interface.addressOfRuntimeOrStatic(ea)

        # If we hit an exception, then we're not a function and all
        # we need to do is to apply our tinfo_t to the address.
        except LookupError:
            result, ok = cls(ea), interface.address.apply_typeinfo(ea, info, **guessed)
            if not ok:
                raise E.DisassemblerError(u"{:s}({:#x}, {!s}{:s}) : Unable to apply the given type ({!s}) to the address ({:#x}).".format('.'.join([__name__, cls.__name__]), ea, utils.string.repr(info_s), ", {:s}".format(utils.string.kwargs(guessed)) if guessed else '', utils.string.repr(info_s), ea))
            return result

        # If we didn't get an exception and we're pointing at a runtime-linked
        # address, then we need to ensure that our type is a pointer to apply it.
        if rt:
            ti = info if builtins.next((guessed[kwd] for kwd in ['force', 'forced'] if kwd in guessed), False) else interface.function.pointer(info)

            # If we didn't get a type back, then we failed during promotion.
            if ti is None:
                raise E.DisassemblerError(u"{:s}({:#x}, {!s}{:s}) : Unable to promote type (\"{:s}\") to a pointer for the runtime-linked address ({:#x}).".format('.'.join([__name__, cls.__name__]), ea, utils.string.repr(info_s), ", {:s}".format(utils.string.kwargs(guessed)) if guessed else '', utils.string.escape(info_s, '"'), ea))

            # Otherwise warn the user about the dirty thing we just did.
            elif ti is not info:
                logging.warning(u"{:s}({:#x}, {!s}{:s}) : Promoted the given type (\"{:s}\") to a pointer before applying it to the runtime-linked address ({:#x}).".format('.'.join([__name__, cls.__name__]), ea, utils.string.repr(info_s), ", {:s}".format(utils.string.kwargs(guessed)) if guessed else '', utils.string.escape(info_s, '"'), ea))

            # Now we can just apply our tinfo_t to the address.
            result, ok = cls(ea), interface.address.apply_typeinfo(ea, ti, **guessed)
            if not ok:
                raise E.DisassemblerError(u"{:s}({:#x}, {!s}{:s}) : Unable to apply the given type ({!s}) to runtime-linked address ({:#x}).".format('.'.join([__name__, cls.__name__]), ea, utils.string.repr(info_s), ", {:s}".format(utils.string.kwargs(guessed)) if guessed else '', utils.string.repr(info_s), ea))
            return result

        # Otherwise, we're pointing at a function and we should be using `function.type`.
        return function.type(ea, info)
    @utils.multicase(ea=internal.types.integer, none=internal.types.none)
    def __new__(cls, ea, none):
        '''Remove the type information from the address `ea`.'''
        result, ok = cls(ea), interface.address.apply_typeinfo(ea, none)
        if not ok:
            raise E.DisassemblerError(u"{:s}({:#x}, {!s}) : Unable to remove the type information from the given address ({:#x}).".format('.'.join([__name__, cls.__name__]), ea, none, ea))
        return result
    @utils.multicase(ea=internal.types.integer, string=internal.types.string)
    @utils.string.decorate_arguments('string')
    def __new__(cls, ea, string, **guessed):
        '''Parse the type information in `string` into an ``idaapi.tinfo_t`` and apply it to the address `ea`.'''
        # We just need to ask IDA to parse this into a tinfo_t for us and then recurse
        # into ourselves. If we received None, then that's pretty much a parsing error.
        ti = internal.declaration.parse(string)
        if ti is None:
            raise E.InvalidTypeOrValueError(u"{:s}({:#x}, {!r}{:s}) : Unable to parse the provided string (\"{:s}\") into a type declaration.".format('.'.join([__name__, cls.__name__]), ea, string, ", {:s}".format(utils.string.kwargs(guessed)) if guessed else '', utils.string.escape(string, '"')))
        return cls(ea, ti, **guessed)

    @utils.multicase()
    @classmethod
    def size(cls):
        '''Return the size of the item at the current address.'''
        return size(ui.current.address())
    @utils.multicase(ea=internal.types.integer)
    @classmethod
    def size(cls, ea):
        '''Return the size of the item at the address `ea`.'''
        ea = interface.address.within(ea)
        return interface.address.size(ea)

    @utils.multicase()
    @classmethod
    def flags(cls):
        '''Return the flags of the item at the current address.'''
        return interface.address.flags(ui.current.address())
    @utils.multicase(ea=internal.types.integer)
    @classmethod
    def flags(cls, ea):
        '''Return the flags of the item at the address `ea`.'''
        return interface.address.flags(interface.address.within(ea))
    @utils.multicase(ea=internal.types.integer, mask=internal.types.integer)
    @classmethod
    def flags(cls, ea, mask):
        '''Return the flags at the address `ea` masked with `mask`.'''
        return interface.address.flags(interface.address.within(ea), mask)
    @utils.multicase(ea=internal.types.integer, mask=internal.types.integer, value=internal.types.integer)
    @classmethod
    def flags(cls, ea, mask, value):
        '''Sets the flags at the address `ea` masked with `mask` set to `value`.'''
        return interface.address.flags(interface.address.within(ea), mask, value)

    @utils.multicase()
    @classmethod
    def initialized(cls):
        '''Return if the current address is initialized.'''
        return cls.initialized(ui.current.address())
    @utils.multicase(ea=internal.types.integer)
    @classmethod
    def initialized(cls, ea):
        '''Return if the address specified by `ea` is initialized.'''
        return interface.address.flags(interface.address.within(ea), idaapi.FF_IVL) == idaapi.FF_IVL
    @utils.multicase(ea=internal.types.integer, size=internal.types.integer)
    @classmethod
    def initialized(cls, ea, size):
        '''Return if the address specified by `ea` up to `size` bytes is initialized.'''
        ea = interface.address.within(ea)
        return all(interface.address.flags(ea + offset, idaapi.FF_IVL) == idaapi.FF_IVL for offset in builtins.range(size))
    initialise = is_initialized = utils.alias(initialized, 'type')

    @utils.multicase()
    @classmethod
    def code(cls):
        '''Return if the item at the current address is marked as code.'''
        return cls.code(ui.current.address())
    @utils.multicase(ea=internal.types.integer)
    @classmethod
    def code(cls, ea):
        '''Return if the item at the address specified by `ea` is marked as code.'''
        flags = interface.address.flags(interface.address.within(ea), idaapi.MS_CLS)
        if flags == idaapi.FF_TAIL:
            return interface.address.flags(interface.address.head(ea), idaapi.MS_CLS) == idaapi.FF_CODE
        return flags == idaapi.FF_CODE
    @utils.multicase(ea=internal.types.integer, size=internal.types.integer)
    @classmethod
    def code(cls, ea, size):
        '''Return if the item at the address specified by `ea` up to `size` bytes is marked as code.'''
        ea, flags = interface.address.within(ea), interface.address.flags(interface.address.head(ea), idaapi.MS_CLS)
        items = {interface.address.flags(ea + offset, idaapi.MS_CLS) for offset in builtins.range(size)}
        return flags == idaapi.FF_CODE and all(flag in {idaapi.FF_TAIL, idaapi.FF_CODE} for flag in items)
    is_code = utils.alias(code, 'type')

    @utils.multicase()
    @classmethod
    def data(cls):
        '''Return if item at the current address is marked as data.'''
        return cls.data(ui.current.address())
    @utils.multicase(ea=internal.types.integer)
    @classmethod
    def data(cls, ea):
        '''Return if item at the address specified by `ea` is marked as data.'''
        flags = interface.address.flags(interface.address.within(ea), idaapi.MS_CLS)
        if flags == idaapi.FF_TAIL:
            return interface.address.flags(interface.address.head(ea), idaapi.MS_CLS) == idaapi.FF_DATA
        return flags == idaapi.FF_DATA
    @utils.multicase(ea=internal.types.integer, size=internal.types.integer)
    @classmethod
    def data(cls, ea, size):
        '''Return if the item at the address specified by `ea` up to `size` bytes is marked as data.'''
        ea, flags = interface.address.within(ea), interface.address.flags(interface.address.head(ea), idaapi.MS_CLS)
        items = {interface.address.flags(ea + offset, idaapi.MS_CLS) for offset in builtins.range(size)}
        return flags == idaapi.FF_DATA and all(flag in {idaapi.FF_TAIL, idaapi.FF_DATA} for flag in items)
    is_data = utils.alias(data, 'type')

    # True if ea marked unknown
    @utils.multicase()
    @classmethod
    def unknown(cls):
        '''Return if the current address is marked as unknown.'''
        return cls.unknown(ui.current.address())
    @utils.multicase(ea=internal.types.integer)
    @classmethod
    def unknown(cls, ea):
        '''Return if the address specified by `ea` is marked as unknown.'''
        flags = interface.address.flags(interface.address.within(ea), idaapi.MS_CLS)
        if flags == idaapi.FF_TAIL:
            return interface.address.flags(interface.address.head(ea), idaapi.MS_CLS) == idaapi.FF_UNK
        return flags == idaapi.FF_UNK
    @utils.multicase(ea=internal.types.integer, size=internal.types.integer)
    @classmethod
    def unknown(cls, ea, size):
        '''Return if the address specified by `ea` up to `size` bytes is marked as unknown.'''
        ea, flags = interface.address.within(ea), interface.address.flags(interface.address.head(ea), idaapi.MS_CLS)
        items = {interface.address.flags(ea + offset, idaapi.MS_CLS) for offset in builtins.range(size)}
        return flags == idaapi.FF_UNK and all(flag in {idaapi.FF_TAIL, idaapi.FF_UNK} for flag in items)
    is_unknown = is_undefined = undefined = utils.alias(unknown, 'type')

    @utils.multicase()
    @classmethod
    def head(cls):
        '''Return if the current address points to the beginning of an item in the database.'''
        return cls.head(ui.current.address())
    @utils.multicase(ea=internal.types.integer)
    @classmethod
    def head(cls, ea):
        '''Return if the address `ea` points to the beginning of an item in the database.'''
        return interface.address.flags(interface.address.within(ea), idaapi.MS_CLS) != idaapi.FF_TAIL
    is_head = utils.alias(head, 'type')

    @utils.multicase()
    @classmethod
    def tail(cls):
        '''Return if the current address does not point to the beginning of an item in the database.'''
        return cls.tail(ui.current.address())
    @utils.multicase(ea=internal.types.integer)
    @classmethod
    def tail(cls, ea):
        '''Return if the address `ea` does not point to the beginning of an item in the database.'''
        return interface.address.flags(interface.address.within(ea), idaapi.MS_CLS) == idaapi.FF_TAIL
    is_tail = utils.alias(tail, 'type')

    @utils.multicase()
    @classmethod
    def alignment(cls):
        '''Return if the current address is defined as an alignment.'''
        return cls.alignment(ui.current.address())
    @utils.multicase(ea=internal.types.integer)
    @classmethod
    def alignment(cls, ea):
        '''Return if the address at `ea` is defined as an alignment.'''
        is_align = idaapi.isAlign if idaapi.__version__ < 7.0 else idaapi.is_align
        return is_align(interface.address.flags(ea))
    is_alignment = utils.alias(alignment, 'type')

    @utils.multicase()
    @classmethod
    def comment(cls):
        '''Return if the current address is commented.'''
        return cls.comment(ui.current.address())
    @utils.multicase(ea=internal.types.integer)
    @classmethod
    def comment(cls, ea):
        '''Return if the address at `ea` is commented.'''
        return True if interface.address.flags(interface.address.within(ea), idaapi.MS_COMM) & idaapi.FF_COMM else False
    is_comment = has_comment = utils.alias(comment, 'type')

    @utils.multicase()
    @classmethod
    def referenced(cls):
        '''Return if the data at the current address is referenced by another address.'''
        return cls.reference(ui.current.address())
    @utils.multicase(ea=internal.types.integer)
    @classmethod
    def referenced(cls, ea):
        '''Return if the data at the address `ea` is referenced by another address.'''
        return True if interface.address.flags(interface.address.within(ea), idaapi.MS_COMM) & idaapi.FF_REF else False
    is_referenced = has_reference = utils.alias(referenced, 'type')

    @utils.multicase()
    @classmethod
    def label(cls):
        '''Return if the current address has a label of any kind.'''
        return cls.label(ui.current.address())
    @utils.multicase(ea=internal.types.integer)
    @classmethod
    def label(cls, ea):
        '''Return if the address at `ea` has a label of any kind.'''
        return idaapi.has_any_name(interface.address.flags(ea)) or cls.dummy(ea) or cls.name(ea)
    has_label = is_label = utils.alias(label, 'type')

    @utils.multicase()
    @classmethod
    def name(cls):
        '''Return if the current address has a custom name.'''
        return cls.name(ui.current.address())
    @utils.multicase(ea=internal.types.integer)
    @classmethod
    def name(cls, ea):
        '''Return if the address at `ea` has a custom name.'''
        return True if interface.address.flags(interface.address.within(ea), idaapi.MS_COMM) & idaapi.FF_NAME else False
    has_customname = is_name = utils.alias(name, 'type')

    @utils.multicase()
    @classmethod
    def dummy(cls):
        '''Return if the current address has an auto-generated name determined by the disassembler.'''
        return cls.dummy(ui.current.address())
    @utils.multicase(ea=internal.types.integer)
    @classmethod
    def dummy(cls, ea):
        '''Return if the address at `ea` has an auto-generated name determined by the disassembler.'''
        return True if interface.address.flags(interface.address.within(ea), idaapi.MS_COMM) & idaapi.FF_LABL else False
    has_dummyname = is_dummy = utils.alias(dummy, 'type')

    @utils.multicase()
    @classmethod
    def auto(cls):
        '''Return if the name for the current address was named automatically.'''
        return cls.auto(ui.current.address())
    @utils.multicase(ea=internal.types.integer)
    @classmethod
    def auto(cls, ea):
        '''Return if the name for the address `ea` was named automatically.'''
        return idaapi.has_auto_name(interface.address.flags(ea))
    @utils.multicase(ea=internal.types.integer)
    @classmethod
    def auto(cls, ea, boolean):
        '''Specify whether the name for the address at `ea` is named automatically depending on the value of `boolean`.'''
        ea = interface.address.within(ea)
        res, _ = idaapi.has_auto_name(ea), idaapi.make_name_auto(ea) if boolean else idaapi.make_name_user(ea)
        return res
    has_autoname = is_auto = utils.alias(auto, 'type')

    @utils.multicase()
    @classmethod
    def public(cls):
        '''Return if the name for the current address is public scoped.'''
        return cls.public(ui.current.address())
    @utils.multicase(ea=internal.types.integer)
    @classmethod
    def public(cls, ea):
        '''Return if the name for the address at `ea` is public scoped.'''
        return idaapi.is_public_name(interface.address.within(ea))
    @utils.multicase(ea=internal.types.integer)
    @classmethod
    def public(cls, ea, boolean):
        '''Update the scope of the name for the address at `ea` to public depending on the value of `boolean`.'''
        ea = interface.address.within(ea)
        res, _ = idaapi.is_public_name(ea), idaapi.make_name_public(ea) if boolean else idaapi.make_name_non_public(ea)
        return res
    has_publicname = is_public = utils.alias(public, 'type')

    @utils.multicase()
    @classmethod
    def weak(cls):
        '''Return if the name for the current address is weak scoped.'''
        return cls.weak(ui.current.address())
    @utils.multicase(ea=internal.types.integer)
    @classmethod
    def weak(cls, ea):
        '''Return if the name for the address at `ea` is weak scoped.'''
        return idaapi.is_weak_name(interface.address.within(ea))
    @utils.multicase(ea=internal.types.integer)
    @classmethod
    def weak(cls, ea, boolean):
        '''Update the scope of the name for the address at `ea` to weak depending on the value of `boolean`.'''
        ea = interface.address.within(ea)
        res, _ = idaapi.is_weak_name(ea), idaapi.make_name_weak(ea) if boolean else idaapi.make_name_non_weak(ea)
        return res
    has_weakname = is_weak = utils.alias(weak, 'type')

    @utils.multicase()
    @classmethod
    def listed(cls):
        '''Return if the current address has a name that is listed.'''
        return cls.listed(ui.current.address())
    @utils.multicase(ea=internal.types.integer)
    @classmethod
    def listed(cls, ea):
        '''Return if the address at `ea` has a name that is listed.'''
        return idaapi.is_in_nlist(interface.address.within(ea))
    @utils.multicase(ea=internal.types.integer)
    @classmethod
    def listed(cls, ea, boolean):
        '''Include the name of the address at `ea` in the names list depending on the value of `boolean`.'''
        ea = interface.address.within(ea)
        res, _ = idaapi.is_in_nlist(), idaapi.show_name(ea) if boolean else idaapi.hide_name(ea)
        return res
    has_listedname = is_listedname = utils.alias(listed, 'type')

    @utils.multicase()
    @classmethod
    def has(cls):
        '''Return if the current address has any type information associated with it.'''
        return cls.has(ui.current.address())
    @utils.multicase(ea=internal.types.integer)
    @classmethod
    def has(cls, ea):
        '''Return if the address at `ea` has any type information associated with it.'''
        try:
            ok = cls(ea) is not None

        # If we got an exception raised, then we were unable to parse this type
        # properly. Prior to failing, check to see if the name is a mangled C++
        # symbol that contains type information.
        except E.InvalidTypeOrValueError as e:
            #logging.warning(u"{:s}.has({:#x}) : Unable to interpret the type information at address {:#x}.".format('.'.join([__name__, type.__name__]), ea, ea), exc_info=True)
            realname = interface.name.get(ea)
            ok = internal.declaration.demangle(realname) != realname
        return ok
    has_typeinfo = info = utils.alias(has, 'type')

    @utils.multicase()
    @classmethod
    def string(cls):
        '''Return if the current address is defined as a string.'''
        return cls.string(ui.current.address())
    @utils.multicase(ea=internal.types.integer)
    @classmethod
    def string(cls, ea):
        '''Return if the address at `ea` is defined as a string.'''
        FF_STRLIT = idaapi.FF_STRLIT if hasattr(idaapi, 'FF_STRLIT') else idaapi.FF_ASCI
        return interface.address.flags(ea, idaapi.DT_TYPE) == FF_STRLIT
    is_string = utils.alias(string, 'type')

    @utils.multicase()
    @classmethod
    def reference(cls):
        '''Return if the current address is referencing another address.'''
        return cls.reference(ui.current.address())
    @utils.multicase(ea=internal.types.integer)
    @classmethod
    def reference(cls, ea):
        '''Return if the address at `ea` is referencing another address.'''
        return True if interface.address.refinfo(ea) or interface.xref.has(ea, True) else False
    is_reference = utils.alias(reference, 'type')

    @utils.multicase()
    @classmethod
    def relocation(cls):
        '''Return if the current address was relocated by a relocation during load.'''
        address, selection = ui.current.address(), ui.current.selection()
        if operator.eq(*(interface.address.head(ea) for ea in selection)):
            return cls.relocation(address)
        return cls.relocation(selection)
    @utils.multicase(ea=internal.types.integer)
    @classmethod
    def relocation(cls, ea):
        '''Return if the address at `ea` was relocated by a relocation during load.'''
        return True if interface.address.refinfo(ea) else False
    @utils.multicase(ea=internal.types.integer, size=internal.types.integer)
    @classmethod
    def relocation(cls, ea, size):
        '''Return if an address at `ea` up to `size` bytes was relocated by a relocation during load.'''
        return any(interface.address.refinfo(ea) for ea in interface.address.items(*bounds))
    @utils.multicase(bounds=interface.bounds_t)
    @classmethod
    def relocation(cls, bounds):
        '''Return if an address within the specified `bounds` was relocated by a relocation during load.'''
        return any(interface.address.refinfo(ea) for ea in interface.address.items(*bounds))
    has_relocation = is_relocation = utils.alias(relocation, 'type')

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
            '''Return the `[type, length]` of the array at the current selection or address.'''
            address, selection = ui.current.address(), ui.current.selection()
            if operator.eq(*(interface.address.head(ea) for ea in selection)):
                return cls(address)
            return cls(selection)
        @utils.multicase(ea=internal.types.integer)
        def __new__(cls, ea):
            '''Return the `[type, length]` of the array at the address specified by `ea`.'''
            return cls(ea, interface.address.size(ea))
        @utils.multicase(bounds=interface.bounds_t)
        def __new__(cls, bounds):
            '''Return the `[type, length]` of the specified `bounds` as an array.'''
            left, right = ea, _ = sorted(bounds)
            return cls(ea, max(0, right - left))
        @utils.multicase(ea=internal.types.integer)
        def __new__(cls, ea, size):
            '''Return the `[type, length]` of the address `ea` if it was an array using the specified `size` (in bytes).'''
            ea = interface.address.head(ea, warn=True)
            info, flags, cb = idaapi.opinfo_t(), interface.address.flags(ea), abs(size)

            # get the opinfo at the current address to verify if there's a structure or not
            ok = idaapi.get_opinfo(ea, idaapi.OPND_ALL, flags, info) if idaapi.__version__ < 7.0 else idaapi.get_opinfo(info, ea, idaapi.OPND_ALL, flags)
            tid = info.tid if ok else idaapi.BADADDR

            # convert it to a pythonic type using the address we were given.
            res = interface.typemap.dissolve(flags, tid, cb, offset=min(ea, ea + size))

            # if it's a list, then validate the result and return it
            if isinstance(res, internal.types.list):
                element, length = res

                # if the address is a string type, then we need to know the prefix size
                # so that we can add it to our length to work around the difference
                # between how these sizes are calc'd in structs versus addresses.
                if isinstance(element, internal.types.tuple) and len(element) == 3:
                    _, width, extra = element
                    return [element, length - extra // width]

                # simply return the element that we resolved.
                return [element, length]

            # this shouldn't ever happen, but if it does then it's a
            # single element array
            return [res, 1]

        @utils.multicase()
        @classmethod
        def has(cls):
            '''Return if the current address is defined as an array of more than 1 element).'''
            return cls.has(ui.current.address())
        @utils.multicase(ea=internal.types.integer)
        @classmethod
        def has(cls, ea):
            '''Return if the address `ea` is defined as an array of more than 1 element).'''
            info, flags, size = idaapi.opinfo_t(), interface.address.flags(ea), interface.address.size(ea)

            # We need to grab the operand information and the structure here, because if it's a
            # variable-length structure, then the size difference we test for might not be an array.
            ok = idaapi.get_opinfo(ea, idaapi.OPND_ALL, flags, info) if idaapi.__version__ < 7.0 else idaapi.get_opinfo(info, ea, idaapi.OPND_ALL, flags)
            sptr = idaapi.get_struc(info.tid if ok else idaapi.BADADDR)

            # If the size is larger than the element size, then it's an array or a string (which we treat as an array).
            return False if sptr and sptr.props & idaapi.SF_VAR else size > interface.address.element(ea, flags)

        @utils.multicase()
        @classmethod
        def member(cls):
            '''Return the type for the member of the array at the current address.'''
            return cls.member(ui.current.address())
        @utils.multicase(ea=internal.types.integer)
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
        @utils.multicase(ea=internal.types.integer)
        @classmethod
        def element(cls, ea):
            '''Return the type information for the member of the array defined at the address specified by `ea`.'''
            ti = type(ea)
            if ti is None:
                raise E.MissingTypeOrAttribute(u"{:s}.element({:#x}) : Unable to fetch any type information from the address at {:#x}.".format('.'.join([__name__, 'type', cls.__name__]), ea, ea))
            return ti.get_array_element() if ti.is_array() else ti
        info = typeinfo = utils.alias(element, 'type.array')

        @utils.multicase()
        @classmethod
        def size(cls):
            '''Return the size of a member in the array at the current address.'''
            return cls.size(ui.current.address())
        @utils.multicase(ea=internal.types.integer)
        @classmethod
        def size(cls, ea):
            '''Return the size of a member in the array at the address specified by `ea`.'''
            ea, flags = interface.address.head(ea, warn=True), interface.address.flags(ea)
            return interface.address.element(ea, flags)

        @utils.multicase()
        @classmethod
        def length(cls):
            '''Return the number of members in the array at the current address.'''
            return cls.length(ui.current.address())
        @utils.multicase(ea=internal.types.integer)
        @classmethod
        def length(cls, ea):
            '''Return the number of members in the array at the address specified by `ea`.'''
            ea = interface.address.head(ea, warn=True)
            sz, ele = interface.address.size(ea), interface.address.element(ea)
            return sz // ele
    is_array = utils.alias(array.has, 'type')

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
        @utils.multicase(ea=internal.types.integer)
        def __new__(cls, ea):
            '''Return the structure type at the address `ea`.'''
            ea = interface.address.head(ea, warn=True)
            identifier = cls.id(ea)
            return internal.structure.new(identifier, ea)

        @utils.multicase()
        @classmethod
        def has(cls):
            '''Return if the current address is defined as a structure.'''
            return cls.has(ui.current.address())
        @utils.multicase(ea=internal.types.integer)
        @classmethod
        def has(cls, ea):
            '''Return if the address at `ea` is defined as a structure.'''
            FF_STRUCT = idaapi.FF_STRUCT if hasattr(idaapi, 'FF_STRUCT') else idaapi.FF_STRU
            return interface.address.flags(ea, idaapi.DT_TYPE) == FF_STRUCT

        @utils.multicase()
        @classmethod
        def id(cls):
            '''Return the identifier of the structure at the current address.'''
            return cls.id(ui.current.address())
        @utils.multicase(ea=internal.types.integer)
        @classmethod
        def id(cls, ea):
            '''Return the identifier of the structure at address `ea`.'''
            FF_STRUCT = idaapi.FF_STRUCT if hasattr(idaapi, 'FF_STRUCT') else idaapi.FF_STRU

            info, ea, flags = idaapi.opinfo_t(), interface.address.head(ea, warn=True), interface.address.flags(ea)
            if flags & idaapi.DT_TYPE != FF_STRUCT:
                raise E.MissingTypeOrAttribute(u"{:s}.id({:#x}) : The type at specified address is not an FF_STRUCT({:#x}) and is instead {:#x}.".format('.'.join([__name__, 'type', cls.__name__]), ea, FF_STRUCT, flags & idaapi.DT_TYPE))

            ok = idaapi.get_opinfo(ea, idaapi.OPND_ALL, flags, info) if idaapi.__version__ < 7.0 else idaapi.get_opinfo(info, ea, idaapi.OPND_ALL, flags)
            if not ok:
                raise E.DisassemblerError(u"{:s}.id({:#x}) : The call to `{:s}({:#x}, {:d}, {:#x})` failed for the address at {:#x}.".format('.'.join([__name__, 'type', cls.__name__]), ea, utils.pycompat.fullname(idaapi.get_opinfo), ea, idaapi.OPND_ALL, flags, ea))
            return info.tid

        @utils.multicase()
        @classmethod
        def folded(cls):
            '''Return whether the structure displayed at the current address has been folded into a single line.'''
            return cls.folded(ui.current.address())
        @utils.multicase(terse=internal.types.bool)
        @classmethod
        def folded(cls, terse):
            '''Modify the way the structure at the current address is displayed as specified by the boolean in `terse`.'''
            return cls.folded(ui.current.address(), terse)
        @utils.multicase(ea=internal.types.integer)
        @classmethod
        def folded(cls, ea):
            '''Return whether the structure at the address `ea` has been folded into a single line.'''
            return True if interface.node.aflags(ea, idaapi.AFL_TERSESTR) else False
        @utils.multicase(ea=internal.types.integer, terse=(internal.types.integer, internal.types.bool))
        @classmethod
        def folded(cls, ea, terse):
            '''Modify the way the structure at the address `ea` is displayed as specified by the boolean in `terse`.'''
            res = interface.node.aflags(ea, idaapi.AFL_TERSESTR)
            interface.node.aflags(ea, idaapi.AFL_TERSESTR, -1 if terse else 0)
            return True if res else False
        @utils.multicase()
        @classmethod
        def fold(cls):
            '''Fold the structure displayed at the current address into a terse format.'''
            return cls.folded(ui.current.address(), True)
        @utils.multicase(ea=internal.types.integer)
        @classmethod
        def fold(cls, ea):
            '''Fold the structure displayed at the address `ea` into a terse format.'''
            return cls.folded(ea, True)
        @utils.multicase()
        @classmethod
        def unfold(cls):
            '''Fold the structure displayed at the current address into a terse format.'''
            return cls.folded(ui.current.address(), False)
        @utils.multicase(ea=internal.types.integer)
        @classmethod
        def unfold(cls, ea):
            '''Fold the structure displayed at the address `ea` into a terse format.'''
            return cls.folded(ea, False)
        show, hide = utils.alias(unfold, 'type.structure'), utils.alias(fold, 'type.structure')

        @utils.multicase()
        @classmethod
        def size(cls):
            '''Return the total size of the structure at the current address.'''
            return cls.size(ui.current.address())
        @utils.multicase(ea=internal.types.integer)
        @classmethod
        def size(cls, ea):
            '''Return the total size of the structure at address `ea`.'''
            id = cls.id(ea)
            ptr = idaapi.get_struc(id)
            return idaapi.get_struc_size(ptr)
    struc = structure   # ns alias (ida-speak)
    is_structure = utils.alias(structure.has, 'type')

    @utils.multicase()
    @classmethod
    def switch(cls):
        '''Return whether the current address is part of a switch_t.'''
        return cls.switch(ui.current.address())
    @utils.multicase(ea=internal.types.integer)
    @classmethod
    def switch(cls, ea):
        '''Return whether the address `ea` is part of a switch_t.'''
        get_switch_info = idaapi.get_switch_info_ex if idaapi.__version__ < 7.0 else idaapi.get_switch_info

        # First check if the address is already part of the switch. This
        # is technically the fast path.
        if get_switch_info(ea):
            return True

        # If we're code being referenced by data, then try all their
        # data refs to see if they're part of a table for a switch.
        elif cls.code(ea) and cls.referenced(ea):
            drefs = (address for address in interface.xref.data_address(ea, descend=False) if not interface.node.identifier(address) and cls.data(address))
            items = (address for address in itertools.chain(*map(functools.partial(interface.xref.data_address, descend=False), drefs)) if cls.code(address))

        # Otherwise, if we're pointing at data and it's referencing something
        # as well as being referenced, then we need its upward refs to check.
        elif cls.data(ea) and cls.reference(ea) and cls.referenced(ea):
            items = (address for address in interface.xref.data_address(ea, descend=False) if not interface.node.identifier(address) and cls.code(address))

        # Any other case means that it's code that's referencing an entry
        # into the switch. We can't do any instruction-based logic here, so
        # we literally follow the reference and then look for a dataref to it.
        elif cls.code(ea) and cls.reference(ea):
            crefs = (address for address in interface.xref.code_address(ea, descend=True))
            drefs = (address for address in itertools.chain(*map(functools.partial(interface.xref.data_address, descend=False), crefs)) if cls.data(address))
            items = (address for address in itertools.chain(*map(functools.partial(interface.xref.data_address, descend=False), drefs)) if cls.code(address))

        # Anything else, isn't a switch because it doesn't have enough references.
        else:
            items = ()

        return True if any(get_switch_info(address) for address in items) else False

    @utils.multicase()
    @classmethod
    def exception(cls, **flags):
        '''Return if the current selection or address is guarded by an exception or part of an exception handler.'''
        address, selection = ui.current.address(), ui.current.selection()
        if operator.eq(*(interface.address.head(ea) for ea in selection)):
            return cls.exception(address, **flags)
        return cls.exception(address, **flags)
    @utils.multicase(ea=(internal.types.integer, interface.bounds_t))
    @classmethod
    def exception(cls, ea, **flags):
        """Return if the address or boundaries in `ea` is guarded by an exception or part of an exception handler.

        If `seh` or `cpp` is specified, then include or exclude that exception type.
        If `guarded` or `try` is true, then return if the address is guarded by an exception.
        If `handler` or `catch` is true, then return if the address is part of an exception handler.
        If `fallthrough` is true, then return if the address is part of the fall-through case for a handler.
        If `filter` or `finally` is true, then return if the address is part of an SEH filter or SEH finalizer (respectively).
        """
        if not hasattr(idaapi, 'TBEA_ANY'):
            logging.fatal(u"{:s}.exception({:s}{:s}) : Support for interacting with exceptions is not available in your version ({:.1f}) of the IDA Pro disassembler (requires {:.1f}).".format('.'.join([__name__, cls.__name__]), "{:#x}".format(ea) if isinstance(ea, internal.types.integer) else interace.bounds_t(*ea), u", {:s}".format(utils.string.kwargs(flags)) if flags else '', idaapi.__version__, 7.7))
            return cls.exception(ea, 0)

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
            logging.warning(u"{:s}.exception({:s}{:s}) : Ignored {:d} unknown parameter{:s} that {:s} passed as flags ({:s}).".format('.'.join([__name__, cls.__name__]), "{:#x}".format(ea) if isinstance(ea, internal.types.integer) else interface.bounds_t(*ea), ", {:s}".format(utils.string.kwargs(flags)) if flags else '', len(leftover), '' if len(leftover) == 1 else 's', 'was' if len(leftover) == 1 else 'were', ', '.join(leftover)))

        # now we can get to the actual api.
        return cls.exception(ea, tryflags)
    @utils.multicase(ea=internal.types.integer, flags=internal.types.integer)
    @classmethod
    def exception(cls, ea, flags):
        '''Return if the address in `ea` is referenced by an exception matching the specified `flags` (``idaapi.TBEA_*``).'''
        is_ea_tryblks = idaapi.is_ea_tryblks if hasattr(idaapi, 'is_ea_tryblks') else utils.fconstant(False)
        return True if is_ea_tryblks(ea, flags) else False
    @utils.multicase(bounds=interface.bounds_t, flags=internal.types.integer)
    @classmethod
    def exception(cls, bounds, flags):
        '''Return if the given `bounds` is referenced by an exception matching the specified `flags` (``idaapi.TBEA_*``).'''
        return any(cls.exception(ea, flags) for ea in interface.address.items(*bounds))
    is_exception = has_exception = utils.alias(exception, 'type')

t = type    # XXX: ns alias
size = utils.alias(type.size, 'type')
is_code = utils.alias(type.code, 'type')
is_data = utils.alias(type.data, 'type')
is_unknown = utils.alias(type.unknown, 'type')
is_head = utils.alias(type.head, 'type')
is_tail = utils.alias(type.tail, 'type')
is_alignment = utils.alias(type.alignment, 'type')

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
        `+` - The type comes from the local type library
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

        `ordinal` - Filter the local types by an ordinal or a list of ordinals
        `name` - Filter the local types by a name or a list of names
        `like` - Filter the names of the local types according to a glob.
        `definition` - Filter the local types by applying a glob to their definition.
        `regex` - Filter the local types by applying a regular-expression to their definition.
        `typeref` or `typedef` - Filter the local types for any that are an alias declared with typedef.
        `defined` or `present` - Filter the local types for any that are defined.
        `size` - Filter the local types according to a size or a list of sizes.
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

    def __new__(cls, *string, **type):
        '''Return the types within the database as a list composed of tuples packed as `(ordinal, name, tinfo_t)`.'''
        return [(ordinal, name, ti) for ordinal, name, ti in cls.iterate(*string, **type)]

    @utils.multicase(library=idaapi.til_t)
    @classmethod
    def __formatter__(cls, library):
        lcls, description = library.__class__, library.desc
        return "<{:s}; <{:s}>>".format('.'.join([lcls.__module__, lcls.__name__]), utils.string.of(description))
    @utils.multicase(library=idaapi.til_t, ordinal=internal.types.integer)
    @classmethod
    def __formatter__(cls, library, ordinal):
        ocls, name = idaapi.tinfo_t, idaapi.get_numbered_type_name(library, ordinal)
        if idaapi.get_type_ordinal(library, name) == ordinal:
            return "<{:s}; #{:d} \"{:s}\">".format('.'.join([lcls.__module__, lcls.__name__]), ordinal, utils.string.of(name))
        count = idaapi.get_ordinal_qty(library)
        if name is None:
            return "<{:s}; #{:s}>".format('.'.join([lcls.__module__, lcls.__name__]), "{:d}".format(ordinal) if 0 < ordinal < count else '???')
        return "<{:s}; #{:s} \"{:s}\">".format('.'.join([lcls.__module__, lcls.__name__]), "{:d}".format(ordinal) if 0 < ordinal < count else '???', name)
    @utils.multicase(library=idaapi.til_t, name=internal.types.string)
    @classmethod
    @utils.string.decorate_arguments('name')
    def __formatter__(cls, library, name):
        ocls, ordinal = idaapi.tinfo_t, idaapi.get_type_ordinal(library, utils.string.to(name))
        return "<{:s}; #{:s} \"{:s}\">".format('.'.join([lcls.__module__, lcls.__name__]), "{:d}".format(ordinal) if ordinal else '???', name)

    __matcher__ = utils.matcher()
    __matcher__.combinator('name', utils.fcondition(utils.finstance(internal.types.string))(utils.fcompose(operator.methodcaller('lower'), utils.fpartial(utils.fpartial, operator.eq)), utils.fcompose(utils.fpartial(map, operator.methodcaller('lower')), internal.types.set, utils.fpartial(utils.fpartial, operator.contains))), operator.itemgetter(1), operator.methodcaller('lower'))
    __matcher__.combinator('like', utils.fcompose(fnmatch.translate, utils.fpartial(re.compile, flags=re.IGNORECASE), operator.attrgetter('match')), operator.itemgetter(1))
    __matcher__.predicate('predicate'), __matcher__.alias('pred', 'predicate')
    __matcher__.combinator('ordinal', utils.fcondition(utils.finstance(internal.types.integer))(utils.fpartial(utils.fpartial, operator.eq), utils.fpartial(utils.fpartial, operator.contains)), operator.itemgetter(0))
    __matcher__.combinator('index', utils.fcondition(utils.finstance(internal.types.integer))(utils.fpartial(utils.fpartial, operator.eq), utils.fpartial(utils.fpartial, operator.contains)), operator.itemgetter(0))
    __matcher__.combinator('definition', utils.fcompose(fnmatch.translate, utils.fpartial(re.compile, flags=re.IGNORECASE), operator.attrgetter('match')), operator.itemgetter(2), "{!s}".format)
    __matcher__.combinator('regex', utils.fcompose(utils.fpartial(re.compile, flags=re.IGNORECASE), operator.attrgetter('match')), operator.itemgetter(2), "{!s}".format)
    __matcher__.mapping('typeref', operator.truth, operator.itemgetter(2), utils.fmap(operator.methodcaller('is_typeref'), operator.methodcaller('present')), all), __matcher__.alias('typedef', 'typeref')
    __matcher__.mapping('defined', operator.truth, operator.itemgetter(2), operator.methodcaller('present')), __matcher__.mapping('present', operator.truth, operator.itemgetter(2), operator.methodcaller('present'))
    __matcher__.mapping('undefined', operator.not_, operator.itemgetter(2), operator.methodcaller('present')), __matcher__.mapping('present', operator.truth, operator.itemgetter(2), operator.methodcaller('present'))

    __matcher__.mapping('integer', operator.truth, operator.itemgetter(2), operator.methodcaller('is_integral'))
    __matcher__.mapping('pointer', operator.truth, operator.itemgetter(2), operator.methodcaller('is_ptr'))
    __matcher__.mapping('function', operator.truth, operator.itemgetter(2), operator.methodcaller('is_func'))
    __matcher__.mapping('float', operator.truth, operator.itemgetter(2), operator.methodcaller('is_floating'))
    __matcher__.mapping('array', operator.truth, operator.itemgetter(2), operator.methodcaller('is_array'))
    __matcher__.mapping('structure', operator.truth, operator.itemgetter(2), operator.methodcaller('is_struct'))
    __matcher__.mapping('union', operator.truth, operator.itemgetter(2), operator.methodcaller('is_union'))
    __matcher__.mapping('enumeration', operator.truth, operator.itemgetter(2), operator.methodcaller('is_enum'))

    __matcher__.combinator('size', utils.fcondition(utils.finstance(internal.types.integer))(utils.fpartial(utils.fpartial, operator.eq), utils.fpartial(utils.fpartial, operator.contains)), operator.itemgetter(2), operator.methodcaller('get_size'))
    __matcher__.boolean('greater', operator.le, operator.itemgetter(2), operator.methodcaller('get_size')), __matcher__.boolean('ge', operator.le, operator.itemgetter(2), operator.methodcaller('get_size'))
    __matcher__.boolean('gt', operator.lt, operator.itemgetter(2), operator.methodcaller('get_size')),
    __matcher__.boolean('less', operator.ge, operator.itemgetter(2), operator.methodcaller('get_size')), __matcher__.boolean('le', operator.ge, operator.itemgetter(2), operator.methodcaller('get_size'))
    __matcher__.boolean('lt', operator.gt, operator.itemgetter(2), operator.methodcaller('get_size'))

    @utils.multicase()
    @classmethod
    def __iterate__(cls):
        '''Iterate through the types within the current type library.'''
        til = idaapi.get_idati()
        return cls.__iterate__(til)
    @utils.multicase(library=idaapi.til_t)
    @classmethod
    def __iterate__(cls, library):
        '''Iterate through the types within the specified type `library`.'''
        count, errors = idaapi.get_ordinal_qty(library), {getattr(idaapi, name) : name for name in dir(idaapi) if name.startswith('sc_')}
        for ordinal in builtins.range(1, count):
            name, serialized = idaapi.get_numbered_type_name(library, ordinal), idaapi.get_numbered_type(library, ordinal)

            # if we didn't get any information returned, then this ordinal was deleted.
            if serialized is None:
                logging.warning(u"{:s}.__iterate__({:s}) : Skipping the type at the current ordinal ({:d}) due to it having been deleted.".format('.'.join([__name__, cls.__name__]), cls.__formatter__(library), ordinal))
                continue

            # try and create a new type from the serialized information. if we
            # fail at this, then this is a critical error.
            ti = cls.get(ordinal, library)
            if ti is None:
                logging.fatal(u"{:s}.__iterate__({:s}) : Skipping the type at the current ordinal ({:d}) due to an error during deserialization.".format('.'.join([__name__, cls.__name__]), cls.__formatter__(library), ordinal))
                continue

            # if the type is empty, then we can just issue a warning and skip it.
            elif ti.empty():
                logging.warning(u"{:s}.__iterate__({:s}) : Skipping the type at the current ordinal ({:d}) due to it being empty.".format('.'.join([__name__, cls.__name__]), cls.__formatter__(library), ordinal))
                continue

            yield ordinal, utils.string.of(name or ''), ti
        return

    @utils.multicase(name=internal.types.string)
    @classmethod
    @utils.string.decorate_arguments('name')
    def iterate(cls, name):
        '''Iterate through the types within the current type library that match the glob specified by `name`.'''
        til = idaapi.get_idati()
        return cls.iterate(til, like=name)
    @utils.multicase(name=internal.types.string, library=idaapi.til_t)
    @classmethod
    @utils.string.decorate_arguments('name')
    def iterate(cls, name, library):
        '''Iterate through the types within the type `library` that match the glob specified by `name`.'''
        return cls.iterate(library, like=name)
    @utils.multicase()
    @classmethod
    @utils.string.decorate_arguments('name', 'like', 'type', 'regex')
    def iterate(cls, **type):
        '''Iterate through the types within the current type library that match the keywords specified by `type`.'''
        til = idaapi.get_idati()
        return cls.iterate(til, **type)
    @utils.multicase(library=idaapi.til_t)
    @classmethod
    @utils.string.decorate_arguments('name', 'like', 'type', 'regex')
    def iterate(cls, library, **type):
        '''Iterate through all of the types in the specified type `library` that match the keywords specified by `type`.'''
        iterable = cls.__iterate__(library)
        for key, value in (type or {'predicate': utils.fconstant(True)}).items():
            iterable = cls.__matcher__.match(key, value, iterable)
        for ordinal, name, tinfo in iterable:
            res, td = idaapi.tinfo_t(), idaapi.typedef_type_data_t(library, ordinal, True)
            if not res.create_typedef(td):
                logging.warning(u"{:s}.iterate({:s}{:s}) : Unable to create a type that references the ordinal ({:d}).".format('.'.join([__name__, cls.__name__]), cls.__formatter__(library), ", {:s}".format(utils.string.kwargs(type)) if type else '', ordinal))
            yield ordinal, name, res
        return

    @utils.multicase(name=internal.types.string)
    @classmethod
    @utils.string.decorate_arguments('name')
    def search(cls, name):
        '''Search through the types within the current type library that match the glob `name` and return the first result.'''
        til = idaapi.get_idati()
        return cls.search(til, like=name)
    @utils.multicase(name=internal.types.string, library=idaapi.til_t)
    @classmethod
    @utils.string.decorate_arguments('name')
    def search(cls, name, library):
        '''Search through the types within the type `library` that match the glob `name` and return the first result.'''
        return cls.search(library, like=name)
    @utils.multicase()
    @classmethod
    @utils.string.decorate_arguments('name', 'like', 'type', 'regex')
    def search(cls, **type):
        '''Search through the types in the current type library that match the keywords specified by `type`.'''
        til = idaapi.get_idati()
        return cls.search(til, **type)
    @utils.multicase(library=idaapi.til_t)
    @classmethod
    @utils.string.decorate_arguments('name', 'like', 'type', 'regex')
    def search(cls, library, **type):
        '''Search through all of the types in the specified type `library` that match the keywords specified by `type`.'''
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

    @utils.multicase(name=internal.types.string)
    @classmethod
    @utils.string.decorate_arguments('name')
    def list(cls, name):
        '''List the types within the current type library that match the glob specified by `name`.'''
        til = idaapi.get_idati()
        return cls.list(til, like=name)
    @utils.multicase(name=internal.types.string, library=idaapi.til_t)
    @classmethod
    @utils.string.decorate_arguments('name')
    def list(cls, name, library):
        '''List the types within the type `library` that match the glob specified by `name`.'''
        return cls.list(library, like=name)
    @utils.multicase()
    @classmethod
    @utils.string.decorate_arguments('name', 'like', 'type', 'regex')
    def list(cls, **type):
        '''List the types within the current type library that match the keywords specified by `type`.'''
        til = idaapi.get_idati()
        return cls.list(til, **type)
    @utils.multicase(library=idaapi.til_t)
    @classmethod
    @utils.string.decorate_arguments('name', 'like', 'type', 'regex')
    def list(cls, library, **type):
        '''List the types within the type `library` that match the keywords specified by `type`.'''
        iterable = cls.__iterate__(library)
        for key, value in (type or {'predicate': utils.fconstant(True)}).items():
            iterable = cls.__matcher__.match(key, value, iterable)

        # Set some reasonable defaults for the list of types
        maxordinal = maxname = maxsize = 0

        # Perform the first pass through our listable grabbing all the lengths.
        listable = []
        for ordinal, name, ti in iterable:
            maxordinal = max(ordinal, maxordinal)
            maxname = max(len(name or ''), maxname)
            maxsize = max(ti.get_size(), maxsize)

            #res, td = idaapi.tinfo_t(), idaapi.typedef_type_data_t(library, ordinal, True)
            #if not res.create_typedef(td):
            #    logging.warning(u"{:s}.list({:s}{:s}) : Unable to create a type that references the ordinal ({:d}).".format('.'.join([__name__, cls.__name__]), cls.__formatter__(library), ", {:s}".format(utils.string.kwargs(type)) if type else '', ordinal))
            listable.append((ordinal, name, ti))

        # We just need to calculate the number of digits for the largest and size.
        cordinal = 2 + utils.string.digits(maxordinal, 10)
        csize = 2 + utils.string.digits(maxsize, 16)

        # Lookup table for figuring out some useful flags
        items = [
            ('T', 'is_typeref'),
        ]
        rlookup = [(q, operator.methodcaller(name)) for q, name in items if hasattr(idaapi.tinfo_t, name)]

        items = [
            ('P', 'is_ptr'),
            ('F', 'is_floating'),
            ('E', 'is_enum'),
            ('I', 'is_integral'),
        ]
        ilookup = [(q, operator.methodcaller(name)) for q, name in items if hasattr(idaapi.tinfo_t, name)]

        items = [
            ('A', 'is_array'),
            ('F', 'is_func'),
            ('V', 'is_vftable'),
            ('C', 'has_vftable'),
            ('S', 'is_struct'),
            ('U', 'is_union'),
        ]
        glookup = [(q, operator.methodcaller(name)) for q, name in items if hasattr(idaapi.tinfo_t, name)]

        # Now we can list each type information located within the type library.
        for ordinal, name, ti in listable:

            # Apparently we can't use builtins.next because python is garbage.
            flibrary = '?' if not ti.present() else 'I' if ti.is_from_subtil() else 'L' if not internal.netnode.has(name) else '+' if ti.get_til() else '-'
            items = [q for q, F in rlookup if F(ti)]
            frtype = items[0] if items else '-'
            items = [q for q, F in ilookup if F(ti)]
            fitype = items[0] if items else '-'
            items = [q for q, F in glookup if F(ti)]
            fgtype = items[0] if items else '-'
            flags = itertools.chain(flibrary, frtype, fitype, fgtype)

            # Render the type and clamp it to some arbitrary size.
            # FIXME: is there some way to calculate the width of the console rather than hardcoding 0xa0 here?
            width, description = 0xa0 - sum([cordinal, 1 + csize, maxname]), "{!s}".format(ti)
            clamped_description = description if len(description) < width else "{:s}...".format(description[:width][:-3])

            # That was it, now we can just display it.
            six.print_(u"{:<{:d}s} {:>+#{:d}x} : {:s} : {:<{:d}s} : {:s}".format("[{:d}]".format(ordinal), cordinal, ti.get_size() if ti.present() else 0, 1 + csize, ''.join(flags), name, maxname, clamped_description))
        return

    @utils.multicase(ordinal=internal.types.integer)
    @classmethod
    def by(cls, ordinal):
        '''Return the type information that is at the given `ordinal`.'''
        return cls.by_index(ordinal)
    @utils.multicase(name=internal.types.string)
    @classmethod
    @utils.string.decorate_arguments('name')
    def by(cls, name):
        '''Return the type information that has the specified `name`.'''
        return cls.by_name(name)
    @utils.multicase(ordinal=internal.types.integer, library=idaapi.til_t)
    @classmethod
    def by(cls, ordinal, library):
        '''Return the type information from the specified `library` that is at the given `ordinal`.'''
        return cls.by_index(ordinal, library)
    @utils.multicase(name=internal.types.string, library=idaapi.til_t)
    @classmethod
    @utils.string.decorate_arguments('name')
    def by(cls, name, library):
        '''Return the type information from the specified `library` that is using the given `name`.'''
        return cls.by_name(name, library)

    @utils.multicase(ordinal=internal.types.integer)
    @classmethod
    def has(cls, ordinal):
        '''Return whether the current type library has a type at the given `ordinal`.'''
        til = idaapi.get_idati()
        return cls.has(ordinal, til)
    @utils.multicase(name=internal.types.string)
    @classmethod
    @utils.string.decorate_arguments('name')
    def has(cls, name):
        '''Return whether the current type library has a type with the specified `name`.'''
        til = idaapi.get_idati()
        return cls.has(name, til)
    @utils.multicase(ordinal=internal.types.integer, library=idaapi.til_t)
    @classmethod
    def has(cls, ordinal, library):
        '''Return whether the provided type `library` has a type at the given `ordinal`.'''
        serialized = idaapi.get_numbered_type(library, ordinal)
        return True if serialized else False
    @utils.multicase(name=internal.types.string, library=idaapi.til_t)
    @classmethod
    @utils.string.decorate_arguments('name')
    def has(cls, name, library):
        '''Return whether the provided type `library` has a type with the specified `name`.'''
        ordinal = idaapi.get_type_ordinal(library, utils.string.to(name))
        return True if ordinal else False

    @utils.multicase(name=internal.types.string)
    @classmethod
    @utils.string.decorate_arguments('name')
    def by_name(cls, name):
        '''Return the type information that has the specified `name`.'''
        til = idaapi.get_idati()
        return cls.by_name(name, til)
    @utils.multicase(name=internal.types.string, library=idaapi.til_t)
    @classmethod
    @utils.string.decorate_arguments('name')
    def by_name(cls, name, library):
        '''Return the type information from the specified `library` that is using the given `name`.'''
        ordinal = idaapi.get_type_ordinal(library, utils.string.to(name))
        if ordinal:
            return cls.by_index(ordinal, library)
        raise E.ItemNotFoundError(u"{:s}.by_name({!r}, {:s}) : No type information was found in the type library with the specified name (\"{:s}\").".format('.'.join([__name__, cls.__name__]), name, cls.__formatter__(library), utils.string.escape(name, '"')))

    @utils.multicase(ordinal=internal.types.integer)
    @classmethod
    def by_index(cls, ordinal):
        '''Return the type information that is at the given `ordinal`.'''
        til = idaapi.get_idati()
        return cls.by_index(ordinal, til)
    @utils.multicase(ordinal=internal.types.integer, library=idaapi.til_t)
    @classmethod
    def by_index(cls, ordinal, library):
        '''Return the type information from the specified `library` that is at the given `ordinal`.'''
        if not (0 < ordinal < idaapi.get_ordinal_qty(library)):
            raise E.ItemNotFoundError(u"{:s}.by_index({:d}, {:s}) : No type information was found in the type library for the specified ordinal ({:d}).".format('.'.join([__name__, cls.__name__]), ordinal, cls.__formatter__(library), ordinal))

        ti, td = idaapi.tinfo_t(), idaapi.typedef_type_data_t(library, ordinal, True)
        if not ti.create_typedef(td):
            raise E.DisassemblerError(u"{:s}.get({:d}, {:s}) : Unable to create a type that references the specified ordinal ({:d}).".format('.'.join([__name__, cls.__name__]), ordinal, cls.__formatter__(library), ordinal))
        return ti

    @utils.multicase(ordinal=internal.types.integer)
    @classmethod
    def name(cls, ordinal):
        '''Return the name of the type from the current type library at the specified `ordinal`.'''
        til = idaapi.get_idati()
        return cls.name(ordinal, til)
    @utils.multicase(ordinal=internal.types.integer, library=idaapi.til_t)
    @classmethod
    def name(cls, ordinal, library):
        '''Return the name of the type from the specified type `library` at the given `ordinal`.'''
        res = idaapi.get_numbered_type_name(library, ordinal)
        if res is None:
            raise E.ItemNotFoundError(u"{:s}.name({:d}, {:s}) : Unable to return the name of specified ordinal ({:d}) from the type library.".format('.'.join([__name__, cls.__name__]), ordinal, cls.__formatter__(library), ordinal))

        # FIXME: which one do we return? the mangled or unmangled name?
        return utils.string.of(res)
    @utils.multicase(ordinal=internal.types.integer, string=internal.types.string)
    @classmethod
    @utils.string.decorate_arguments('string')
    def name(cls, ordinal, string, **mangled):
        '''Set the name of the type at the specified `ordinal` from the current library to `string`.'''
        til = idaapi.get_idati()
        return cls.name(ordinal, string, til, **mangled)
    @utils.multicase(ordinal=internal.types.integer, string=internal.types.string, library=idaapi.til_t)
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

    @utils.multicase(name=internal.types.string)
    @classmethod
    @utils.string.decorate_arguments('name')
    def ordinal(cls, name):
        '''Return the ordinal number for the type with the specified `name`.'''
        til = idaapi.get_idati()
        return cls.ordinal(name, til)
    @utils.multicase(name=internal.types.string, library=idaapi.til_t)
    @classmethod
    @utils.string.decorate_arguments('name')
    def ordinal(cls, name, library):
        '''Return the ordinal number for the type from the given `library` with the specified `name`.'''
        res = idaapi.get_type_ordinal(library, utils.string.to(name))
        if not res:
            raise E.ItemNotFoundError(u"{:s}.ordinal({!r}, {:s}) : Could not find a type with the specified name (\"{:s}\") within the type library.".format('.'.join([__name__, cls.__name__]), name, cls.__formatter__(library), utils.string.escape(name, '"')))
        return res

    @utils.multicase(ordinal=internal.types.integer)
    @classmethod
    def get(cls, ordinal):
        '''Get the type information at the given `ordinal` of the current type library and return it.'''
        til = idaapi.get_idati()
        return cls.get(ordinal, til)
    @utils.multicase(name=internal.types.string)
    @classmethod
    @utils.string.decorate_arguments('name')
    def get(cls, name):
        '''Get the type information with the given `name` from the current type library and return it.'''
        til = idaapi.get_idati()
        return cls.get(name, til)
    @utils.multicase(ordinal=internal.types.integer, library=idaapi.til_t)
    @classmethod
    def get(cls, ordinal, library):
        '''Get the type information at the given `ordinal` of the specified type `library` and return it.'''
        if 0 < ordinal < idaapi.get_ordinal_qty(library):
            serialized = idaapi.get_numbered_type(library, ordinal)
            return interface.tinfo.get(library, *serialized)
        raise E.ItemNotFoundError(u"{:s}.get({:d}, {:s}) : No type information was found for the specified ordinal ({:d}) in the type library.".format('.'.join([__name__, cls.__name__]), ordinal, cls.__formatter__(library), ordinal))
    @utils.multicase(name=internal.types.string, library=idaapi.til_t)
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

    @utils.multicase(serialized=internal.types.tuple)
    @classmethod
    def get(cls, serialized):
        '''Convert the `serialized` type information from the current type library and return it.'''
        til = idaapi.get_idati()
        return cls.get(serialized, til)
    @utils.multicase(serialized=internal.types.tuple, library=idaapi.til_t)
    @classmethod
    def get(cls, serialized, library):
        '''Convert the `serialized` type information from the specified type `library` and return it.'''
        errors = {getattr(idaapi, name) : name for name in dir(idaapi) if name.startswith('sc_')}
        sclass = serialized[4] if len(serialized) == 5 else getattr(idaapi, 'sc_unk', 0)

        # we need to generate a description so that we can format error messages the user will understand.
        names = ['type', 'fields', 'cmt', 'fieldcmts']
        items = itertools.chain(["{:s}={!r}".format(name, item) for name, item in zip(names, serialized) if item], ["{:s}={!s}".format('sclass', sclass)] if len(serialized) == 5 else [])
        description = [item for item in items]

        # try to deserialize the type so that we can return it to the caller.
        # if we were unable to do that, then we need to log a critical error
        # that's somewhat useful before returning None back to the user.
        result = interface.tinfo.get(library, *serialized)
        if not result:
            logging.fatal(u"{:s}.get({:s}{:s}) : Unable to deserialize the information for a type using the serialized storage class {:s}.".format('.'.join([__name__, cls.__name__]), cls.__formatter__(library), ", {:s}".format(', '.join(description)) if description else '', "{:s}({:d})".format(errors[sclass], sclass) if sclass in errors else "({:d})".format(sclass)))
        return result

    @utils.multicase(ordinal=internal.types.integer, info=(internal.types.string, idaapi.tinfo_t))
    @classmethod
    def set(cls, ordinal, info):
        '''Assign the type information `info` to the type at the specified `ordinal` of the current type library.'''
        til = idaapi.get_idati()
        return cls.set(ordinal, info, til)
    @utils.multicase(ordinal=internal.types.integer, name=internal.types.string, info=(internal.types.string, idaapi.tinfo_t))
    @classmethod
    @utils.string.decorate_arguments('name')
    def set(cls, ordinal, name, info, **mangled):
        '''Assign the type information `info` with the specified `name` to the given `ordinal` of the current type library.'''
        til = idaapi.get_idati()
        return cls.set(ordinal, name, info, til, **mangled)
    @utils.multicase(ordinal=internal.types.integer, info=(internal.types.string, idaapi.tinfo_t), library=idaapi.til_t)
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
    @utils.multicase(ordinal=internal.types.integer, name=internal.types.string, string=internal.types.string, library=idaapi.til_t)
    @classmethod
    @utils.string.decorate_arguments('name', 'string')
    def set(cls, ordinal, name, string, library, **mangled):
        '''Assign the type information in `string` with the specified `name` to the specified `ordinal` of the given type `library`.'''
        ti = internal.declaration.parse(string)
        if ti is None:
            raise E.InvalidTypeOrValueError(u"{:s}.set({:d}, {!r}, {!r}, {:s}{:s}) : Unable to parse the specified type declaration ({!s}).".format('.'.join([__name__, cls.__name__]), ordinal, name, string, cls.__formatter__(library), ", {:s}".format(utils.string.kwargs(mangled)) if mangled else '', utils.string.repr(string)))
        return cls.set(ordinal, name, ti, library, **mangled)
    @utils.multicase(ordinal=internal.types.integer, name=internal.types.string, info=idaapi.tinfo_t, library=idaapi.til_t)
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
        res = idaapi.set_numbered_type(library, ordinal, idaapi.NTF_REPLACE | flags, utils.string.to(identifier), type, fields, cmt.decode('latin1') if isinstance(cmt, internal.types.bytes) else cmt, fieldcmts if isinstance(fieldcmts, internal.types.bytes) else fieldcmts.encode('latin1'), sclass)
        if res == idaapi.TERR_WRONGNAME:
            raise E.DisassemblerError(u"{:s}.set({:d}, {!r}, {!r}, {:s}) : Unable to set the type information for the ordinal ({:d}) in the type library with the given name ({!r}) due to error {:s}.".format('.'.join([__name__, cls.__name__]), ordinal, name, "{!s}".format(info), cls.__formatter__(library), ordinal, identifier, "{:s}({:d})".format(errors[res], res) if res in errors else "code ({:d})".format(res)))
        elif res != idaapi.TERR_OK:
            raise E.DisassemblerError(u"{:s}.set({:d}, {!r}, {!r}, {:s}) : Unable to set the type information for the ordinal ({:d}) in the specified type library due to error {:s}.".format('.'.join([__name__, cls.__name__]), ordinal, name, "{!s}".format(info), cls.__formatter__(library), ordinal, "{:s}({:d})".format(errors[res], res) if res in errors else "code ({:d})".format(res)))
        return ti

    @utils.multicase(ordinal=internal.types.integer)
    @classmethod
    def remove(cls, ordinal):
        '''Remove the type information at the specified `ordinal` of the current type library.'''
        til = idaapi.get_idati()
        return cls.remove(ordinal, til)
    @utils.multicase(ordinal=internal.types.integer, library=idaapi.til_t)
    @classmethod
    def remove(cls, ordinal, library):
        '''Remove the type information at the `ordinal` of the specified type `library`.'''
        res = cls.get(ordinal, library)
        if not idaapi.del_numbered_type(library, ordinal):
            raise E.ItemNotFoundError(u"{:s}.remove({:d}, {:s}) : Unable to delete the type information at the specified ordinal ({:d}) of the type library.".format('.'.join([__name__, cls.__name__]), ordinal, cls.__formatter__(library), ordinal))
        return res
    @utils.multicase(name=internal.types.string)
    @classmethod
    @utils.string.decorate_arguments('name')
    def remove(cls, name, **mangled):
        '''Remove the type information with the specified `name` from the current type library.'''
        til = idaapi.get_idati()
        return cls.remove(name, til, **mangled)
    @utils.multicase(name=internal.types.string, library=idaapi.til_t)
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

    @utils.multicase(name=internal.types.string)
    @classmethod
    @utils.string.decorate_arguments('name')
    def add(cls, name, **mangled):
        '''Add an empty type with the provided `name` to the current type library.'''
        til = idaapi.get_idati()
        return cls.add(name, til, **mangled)
    @utils.multicase(name=internal.types.string, library=idaapi.til_t)
    @classmethod
    @utils.string.decorate_arguments('name')
    def add(cls, name, library, **mangled):
        '''Add an empty type with the provided `name` to the specified type `library`.'''
        ti = cls.parse(' '.join(['struct', name]))
        return cls.add(name, ti, library, **mangled)
    @utils.multicase(name=internal.types.string, info=(internal.types.string, idaapi.tinfo_t))
    @classmethod
    @utils.string.decorate_arguments('name')
    def add(cls, name, info, **mangled):
        '''Add the type information in `info` to the current type library using the provided `name`.'''
        til = idaapi.get_idati()
        return cls.add(name, info, til, **mangled)
    @utils.multicase(name=internal.types.string, string=internal.types.string, library=idaapi.til_t)
    @classmethod
    @utils.string.decorate_arguments('name')
    def add(cls, name, string, library, **mangled):
        '''Add the type information in `string` to the specified type `library` using the provided `name`.'''
        ti = internal.declaration.parse(string)
        if ti is None:
            raise E.InvalidTypeOrValueError(u"{:s}.add({!r}, {!r}, {:s}{:s}) : Unable to parse the specified type declaration ({:s}).".format('.'.join([__name__, cls.__name__]), name, string, cls.__formatter__(library), ", {:s}".format(utils.string.kwargs(mangled)) if mangled else '', utils.string.repr(string)))
        return cls.add(name, ti, library, **mangled)
    @utils.multicase(name=internal.types.string, info=idaapi.tinfo_t, library=idaapi.til_t)
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
        res = idaapi.set_numbered_type(library, ordinal, flags, utils.string.to(identifier), type, fields, cmt.decode('latin1') if isinstance(cmt, internal.types.bytes) else cmt, fieldcmts if isinstance(fieldcmts, internal.types.bytes) else fieldcmts.encode('latin1'), sclass)
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
        '''Return the number of types that are available within the current type library.'''
        til = idaapi.get_idati()
        return cls.count(til)
    @utils.multicase(library=idaapi.til_t)
    @classmethod
    def count(cls, library):
        '''Return the number of types that are available within the specified type `library`.'''
        return idaapi.get_ordinal_qty(library)

    @utils.multicase(string=internal.types.string)
    @classmethod
    def declare(cls, string, **flags):
        """Parse the given `string` into an ``idaapi.tinfo_t`` using the current type library and return it.

        If the integer `flags` is provided, then use the specified flags (``idaapi.PT_*``) when parsing the `string`.
        """
        til = idaapi.cvar.idati if idaapi.__version__ < 7.0 else idaapi.get_idati()
        return cls.declare(string, til, **flags)
    @utils.multicase(string=internal.types.string, library=idaapi.til_t)
    @classmethod
    def declare(cls, string, library):
        '''Parse the given `string` into an ``idaapi.tinfo_t`` using the specified type `library` and return it.'''
        return cls.declare(string, library, idaapi.PT_TYP)
    @utils.multicase(string=internal.types.string, library=idaapi.til_t)
    @classmethod
    def declare(cls, string, library, flags):
        '''Parse the given `string` into an ``idaapi.tinfo_t`` for the specified type `library` with `flags` and return it.'''
        ti, flag = idaapi.tinfo_t(), flags | idaapi.PT_SIL

        # Firstly we need to ';'-terminate the type the user provided in order
        # for IDA's parser to understand it.
        terminated = string if string.rstrip().endswith(';') else "{:s};".format(string)

        # Ask IDA to parse this into a tinfo_t for us. We default to the silent flag so
        # that we're responsible for handling it if there's a parsing error of some sort.
        if idaapi.__version__ < 6.9:
            ok, name = idaapi.parse_decl2(library, terminated, None, ti, flag), None
        elif idaapi.__version__ < 7.0:
            ok, name = idaapi.parse_decl2(library, terminated, ti, flag), None
        else:
            name = idaapi.parse_decl(ti, library, terminated, flag)
            ok = name is not None

        # If we were explicitly asked to be silent (using the "flags" parameter),
        # then we avoid raising an exception entirely and return None on failure.
        if not ok and flags & idaapi.PT_SIL:
            return None

        # If we couldn't parse the type we were given, then simply bail.
        elif not ok:
            raise E.DisassemblerError(u"{:s}.declare({!r}, {:s}, {:#x}) : Unable to parse the provided string into a valid type.".format('.'.join([__name__, cls.__name__]), string, cls.__formatter__(library), flags))

        # If we were given the idaapi.PT_VAR flag, then we return the parsed name too.
        string = utils.string.of(name)
        logging.info(u"{:s}.declare({!r}, {:s}, {:#x}) : Successfully parsed the given string into a valid type{:s}.".format('.'.join([__name__, cls.__name__]), string, cls.__formatter__(library), flags, " ({:s})".format(string) if string else ''))
        return (string or u'', ti) if flag & idaapi.PT_VAR else ti
    parse = utils.alias(declare, 'types')

    @utils.multicase(info=idaapi.tinfo_t)
    @classmethod
    def dereference(cls, info):
        '''Return the target type of the pointer that is specified by `info`.'''
        if not info.has_details():
            raise E.MissingTypeOrAttribute(u"{:s}.dereference(\"{:s}\") : The provided type information ({!r}) does not contain any details.".format('.'.join([__name__, cls.__name__]), utils.string.escape("{!s}".format(info), '"'), "{!s}".format(info)))

        if not info.is_ptr():
            raise E.InvalidTypeOrValueError(u"{:s}.dereference(\"{:s}\") : The provided type information ({!r}) is not a pointer.".format('.'.join([__name__, cls.__name__]), utils.string.escape("{!s}".format(info), '"'), "{!s}".format(info)))

        pi = idaapi.ptr_type_data_t()
        if not info.get_ptr_details(pi):
            raise E.DisassemblerError(u"{:s}.dereference(\"{:s}\") : Unable to get the pointer type data from the provided type information ({!r}).".format('.'.join([__name__, cls.__name__]), utils.string.escape("{!s}".format(info), '"'), "{!s}".format(info)))
        return pi.obj_type

    @utils.multicase(type=(idaapi.tinfo_t, idaapi.struc_t, internal.structure.structure_t, internal.types.string))
    @classmethod
    def pointer(cls, type):
        '''Create a pointer that references the specified `type`.'''
        return cls.pointer(type, 0, 0)
    @utils.multicase(type=(idaapi.tinfo_t, idaapi.struc_t, internal.structure.structure_t, internal.types.string), size=internal.types.integer)
    @classmethod
    def pointer(cls, type, size):
        '''Create a pointer of `size` bytes that references the specified `type`.'''
        return cls.pointer(type, size, 0)
    @utils.multicase(type=internal.structure.structure_t, size=internal.types.integer, attributes=internal.types.integer)
    @classmethod
    def pointer(cls, type, size, attributes, **fields):
        '''Create a pointer of `size` bytes that references the specified structure `type` with the given `size` and extended `attributes`.'''
        return cls.pointer(type.ptr, size, attributes, **fields)
    @utils.multicase(sptr=idaapi.struc_t, size=internal.types.integer, attributes=internal.types.integer)
    @classmethod
    def pointer(cls, sptr, size, attributes, **fields):
        '''Create a pointer of `size` bytes that references the structure specified by `sptr` with the given `size` and extended `attributes`.'''
        ti = type(sptr.id)
        return cls.pointer(ti, size, attributes, **fields)
    @utils.multicase(string=internal.types.string, size=internal.types.integer, attributes=internal.types.integer)
    @classmethod
    @utils.string.decorate_arguments('string')
    def pointer(cls, string, size, attributes, **fields):
        '''Create a pointer of `size` bytes that references the type specified by `string` with the given `size` and extended `attributes`.'''
        ti = internal.declaration.parse(string)
        if ti is None:
            raise E.InvalidTypeOrValueError(u"{:s}.pointer({!r}, {:d}, {:#x}{:s}) : Unable to parse the given type declaration (\"{!s}\") for the pointer target.".format('.'.join([__name__, cls.__name__]), string, size, attributes, ", {:s}".format(utils.string.kwargs(fields)) if fields else '', utils.string.escape(string, '"')))
        return cls.pointer(ti, size, attributes, **fields)
    @utils.multicase(info=idaapi.tinfo_t, size=internal.types.integer, attributes=internal.types.integer)
    @classmethod
    def pointer(cls, info, size, attributes, **fields):
        '''Create a pointer of `size` bytes that references the type specified by `info` with the given `size` and extended `attributes`.'''
        pi = idaapi.ptr_type_data_t()
        pi.obj_type = info
        pi.based_ptr_size = size
        pi.taptr_bits = idaapi.TAH_HASATTRS | attributes if attributes else 0

        # Verify that all of the fields that we were given are actually part of the ptr_type_data_t
        if any(not hasattr(pi, name) for name in fields):
            missing = {name for name in fields if not hasattr(pi, name)}
            raise E.InvalidParameterError(u"{:s}.pointer(\"{:s}\", {:d}, {:d}{:s}) : Unable to assign to the field{:s} ({:s}) of the pointer type data because {:s} not exist.".format('.'.join([__name__, cls.__name__]), utils.string.escape("{!s}".format(info), '"'), size, attributes, u", {:s}".format(utils.string.kwargs(fields)) if fields else '', '' if len(missing) == 1 else 's', ', '.join(sorted(missing)), 'it does' if len(missing) == 1 else 'they do'))
        [setattr(pi, name, value) for name, value in fields.items()]

        # Use the ptr_type_data_t to create a pointer and return it.
        ti = idaapi.tinfo_t()
        if not ti.create_ptr(pi):
            raise E.DisassemblerError(u"{:s}.pointer(\"{:s}\", {:d}, {:d}{:s}) : Unable to create a pointer for the provided type information ({!r}).".format('.'.join([__name__, cls.__name__]), utils.string.escape("{!s}".format(info), '"'), size, attributes, u", {:s}".format(utils.string.kwargs(fields)) if fields else '', "{!s}".format(info)))
        return ti

    @utils.multicase(info=idaapi.tinfo_t)
    @classmethod
    def array(cls, info):
        '''Return a tuple containing the element type and length of the array specified by `info`.'''
        if not info.has_details():
            raise E.MissingTypeOrAttrbute(u"{:s}.array(\"{:s}\") : The provided type information ({!r}) does not contain any details.".format('.'.join([__name__, cls.__name__]), utils.string.escape("{!s}".format(info), '"'), "{!s}".format(info)))

        if not info.is_array():
            raise E.InvalidTypeOrValueError(u"{:s}.array(\"{:s}\") : The provided type information ({!r}) is not an array.".format('.'.join([__name__, cls.__name__]), utils.string.escape("{!s}".format(info), '"'), "{!s}".format(info)))

        ai = idaapi.array_type_data_t()
        if not info.get_array_details(ai):
            raise E.DisassemblerError(u"{:s}.array(\"{:s}\") : Unable to get the array type data from the provided type information ({!r}).".format('.'.join([__name__, cls.__name__]), utils.string.escape("{!s}".format(info), '"'), "{!s}".format(info)))
        return ai.elem_type, ai.nelems
    @utils.multicase(element=(idaapi.tinfo_t, idaapi.struc_t, internal.structure.structure_t, internal.types.string), length=internal.types.integer)
    @classmethod
    def array(cls, element, length):
        '''Create an array of the given `element` with the specified `length`.'''
        return cls.array(element, length, 0)
    @utils.multicase(type=internal.structure.structure_t, length=internal.types.integer, base=internal.types.integer)
    @classmethod
    def array(cls, type, length, base):
        '''Create an array of the specified structure `type` with the given `length` and `base`.'''
        return cls.array(type.ptr, length, base)
    @utils.multicase(sptr=idaapi.struc_t, length=internal.types.integer, base=internal.types.integer)
    @classmethod
    def array(cls, sptr, length, base):
        '''Create an array of the structure specified by `sptr` with the given `length` and `base`.'''
        ti = type(sptr.id)
        return cls.array(ti, length, base)
    @utils.multicase(string=internal.types.string, length=internal.types.integer, base=internal.types.integer)
    @classmethod
    @utils.string.decorate_arguments('string')
    def array(cls, string, length, base):
        '''Create an array of the element specified by `string` with the given `length` and `base`.'''
        ti = internal.declaration.parse(string)
        if ti is None:
            raise E.InvalidTypeOrValueError(u"{:s}.array({!r}, {:d}, {:d}) : Unable to parse the given type declaration (\"{!s}\") for the array element.".format('.'.join([__name__, cls.__name__]), string, length, base, utils.string.escape(string, '"')))
        return cls.array(ti, length, base)
    @utils.multicase(element=idaapi.tinfo_t, length=internal.types.integer, base=internal.types.integer)
    @classmethod
    def array(cls, element, length, base):
        '''Create an array of the given `element` with the specified `length` and `base`.'''
        ai = idaapi.array_type_data_t()
        ai.elem_type = element
        ai.nelems = length
        ai.base = base

        ti = idaapi.tinfo_t()
        if not ti.create_array(ai):
            raise E.DisassemblerError(u"{:s}.array(\"{:s}\", {:d}, {:d}) : Unable to create an array using the provided type information ({!r}).".format('.'.join([__name__, cls.__name__]), utils.string.escape("{!s}".format(element), '"'), length, base, "{!s}".format(element)))
        return ti

    @utils.multicase(info=idaapi.tinfo_t)
    @classmethod
    def typedef(cls, info):
        '''Return the name and type of the typedef given by `info`.'''
        if not info.has_details():
            raise E.MissingTypeOrAttribute(u"{:s}.typedef(\"{:s}\") : The provided type information ({!r}) does not contain any details.".format('.'.join([__name__, cls.__name__]), utils.string.escape("{!s}".format(info), '"'), "{!s}".format(info)))

        if not info.is_typeref():
            raise E.InvalidTypeOrValueError(u"{:s}.typedef(\"{:s}\") : The provided type information ({!r}) is not a type definition.".format('.'.join([__name__, cls.__name__]), utils.string.escape("{!s}".format(info), '"'), "{!s}".format(info)))

        library = interface.tinfo.library(info)
        name, ordinal = info.get_type_name(), interface.tinfo.ordinal(info, library)
        return name, cls.get(ordinal, library) if ordinal else None
    @utils.multicase(ordinal=internal.types.integer)
    @classmethod
    def typedef(cls, ordinal):
        '''Create a reference to a type with the specified `ordinal` from the current type library and return it.'''
        res = interface.tinfo.reference(ordinal, interface.tinfo.library())
        if not res:
            raise E.MissingTypeOrAttribute(u"{:s}.typedef({:d}) : The specified ordinal ({:d}) does not exist in the current type library.".format('.'.join([__name__, cls.__name__]), ordinal, ordinal))
        return res
    @utils.multicase(name=internal.types.string)
    @classmethod
    def typedef(cls, name, **missing):
        """Create a reference to a type that is using the specified `name`.

        If `missing` is specified as true, then the name is not required to exist within the current type library.
        """
        res = interface.tinfo.reference(name) if missing.get('missing', False) else interface.tinfo.reference(name, interface.tinfo.library())
        if not res:
            raise E.MissingTypeOrAttribute(u"{:s}.typedef({!r}{:s}) : A type with the name \"{:s}\" does not exist in the current type library.".format('.'.join([__name__, cls.__name__]), name, u", {:s}".format(utils.string.kwargs(missing)) if missing else '', utils.string.escape(name, '"')))
        return res
    @utils.multicase(name=(internal.types.string, internal.types.integer), library=idaapi.til_t)
    @classmethod
    def typedef(cls, name, library):
        '''Create a reference to a type with the given type `name` from the specified type `library`.'''
        ordinal = cls.ordinal(name, library) if isinstance(name, internal.types.string) else name
        res = interface.tinfo.reference(ordinal, library)
        if not res:
            raise E.MissingTypeOrAttribute(u"{:s}.typedef({!r}, {:s}) : A type with the {:s} does not exist in the specified type library.".format('.'.join([__name__, cls.__name__]), "{:d}".format(name) if isinstance(name, internal.types.integer) else name, cls.__formatter__(library), "given ordinal ({:d})".format(name) if isinstance(name, internal.types.integer) else "name \"{:s}\"".format(name, utils.string.escape(name, '"'))))
        return ti
    typeref = utils.alias(typedef, 'types')

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
    @classmethod
    def data_down(cls):
        '''Return all the ``ref_t`` that is referenced by the current address as data.'''
        return cls.data_down(ui.current.address())
    @utils.multicase(ea=internal.types.integer)
    @classmethod
    def data_down(cls, ea):
        '''Return all the ``ref_t` that is referenced by the address `ea` as data.'''
        return sorted(interface.xref.data(ea, True))
    dd = utils.alias(data_down, 'xref')

    @utils.multicase()
    @classmethod
    def data_up(cls):
        '''Return all the ``ref_t` that references to the current address as data.'''
        return cls.data_up(ui.current.address())
    @utils.multicase(ea=internal.types.integer)
    @classmethod
    def data_up(cls, ea):
        '''Return all the ``ref_t` that references the address `ea` as data.'''
        return sorted(itertools.chain(*(interface.xref.data(ea, False) for ea in interface.address.references(ea))))
    du = utils.alias(data_up, 'xref')

    @utils.multicase()
    @classmethod
    def code_down(cls):
        '''Return all the ``ref_t`` that is referenced by the current address as code.'''
        return cls.code_down(ui.current.address())
    @utils.multicase(ea=internal.types.integer)
    @classmethod
    def code_down(cls, ea):
        '''Return all the ``ref_t`` that is referenced by the address `ea` as code.'''
        return sorted(interface.xref.code(ea, True))
    cd = utils.alias(code_down, 'xref')

    @utils.multicase()
    @classmethod
    def code_up(cls):
        '''Return all the ``ref_t` that references to the current address as code.'''
        return cls.code_up(ui.current.address())
    @utils.multicase(ea=internal.types.integer)
    @classmethod
    def code_up(cls, ea):
        '''Return all the ``ref_t` that references the address `ea` as code.'''
        return sorted(interface.xref.code(ea, False))
    cu = utils.alias(code_up, 'xref')

    @utils.multicase()
    @classmethod
    def up(cls):
        '''Return all of the addresses that reference the current address.'''
        return cls.up(ui.current.address())
    @utils.multicase(ea=internal.types.integer)
    @classmethod
    def up(cls, ea):
        '''Return all of the addresses that reference the address `ea`.'''
        return sorted(itertools.chain(*(interface.xref.any(ea, False) for ea in interface.address.references(ea))))
    u = utils.alias(up, 'xref')

    # All locations that are referenced by the specified address
    @utils.multicase()
    @classmethod
    def down(cls):
        '''Return all of the addresses that are referred by the current address.'''
        return cls.down(ui.current.address())
    @utils.multicase(ea=internal.types.integer)
    @classmethod
    def down(cls, ea):
        '''Return all of the addresses that are referred by the address `ea`.'''
        return sorted(interface.xref.any(ea, True))
    d = utils.alias(down, 'xref')

    @utils.multicase(target=internal.types.integer)
    @classmethod
    def add_code(cls, target, **reftype):
        '''Add a code reference from the current address to `target`.'''
        return cls.add_code(ui.current.address(), target, **reftype)
    @utils.multicase(ea=internal.types.integer, target=internal.types.integer)
    @classmethod
    def add_code(cls, ea, target, **reftype):
        """Add a code reference from address `ea` to `target`.

        If the integer `reftype` is set, then use this value as the flow type.
        """
        ea, target = interface.address.head(ea, target, warn=True)
        near = segment.bounds(ea) == segment.bounds(target)

        flowtype = reftype.get('flowtype', reftype.get('reftype', idaapi.XREF_USER))
        if flowtype & idaapi.XREF_MASK:
            pass
        elif interface.instruction.feature(ea) & idaapi.CF_CALL == idaapi.CF_CALL:
            flowtype |= idaapi.fl_CN if near else idaapi.fl_CF
        else:
            flowtype |= idaapi.fl_JN if near else idaapi.fl_JF
        return cls.add_code(ea, target, flowtype)
    @utils.multicase(ea=internal.types.integer, target=internal.types.integer, flowtype=internal.types.integer)
    @classmethod
    def add_code(cls, ea, target, flowtype):
        '''Add a code reference from address `ea` to `target` using the specified `flowtype`.'''
        interface.xref.add_code(ea, target, flowtype)
        return target in interface.xref.code_address(ea, descend=True)
    ac = utils.alias(add_code, 'xref')

    @utils.multicase(target=internal.types.integer)
    @classmethod
    def add_data(cls, target, **reftype):
        '''Add a data reference from the current address to `target`.'''
        return cls.add_data(ui.current.address(), target, **reftype)
    @utils.multicase(ea=internal.types.integer, target=internal.types.integer)
    @classmethod
    def add_data(cls, ea, target, **reftype):
        """Add a data reference from the address `ea` to `target`.

        If the boolean `reference`, `offset`, or both `read` and `write` is true, the specify that the reference is an address to the target.
        If the boolean `write` is true, then specify that the reference is writing to the target.
        If the integer `reftype` is set, then use this value as the data type.
        """
        ea, target = interface.address.head(ea, target, warn=True)
        datatype = reftype.get('datatype', reftype.get('reftype', idaapi.XREF_USER))
        if all(reftype.get(attribute, False) for attribute in ['read', 'write']) or any(reftype[attribute] for attribute in ['offset', 'ref', 'reference'] if attribute in reftype):
            datatype = (datatype & ~idaapi.XREF_MASK) | idaapi.dr_O
        elif reftype.get('write', False):
            datatype = (datatype & ~idaapi.XREF_MASK) | idaapi.dr_W
        elif reftype.get('read', False):
            datatype = (datatype & ~idaapi.XREF_MASK) | idaapi.dr_R
        else:   # informational
            datatype = (datatype & ~idaapi.XREF_MASK) | idaapi.dr_I
        datatype|= idaapi.dr_O if reftype.get('offset', reftype.get('ref', False)) else idaapi.dr_W if reftype.get('write', False) else idaapi.dr_R
        return cls.add_data(ea, target, datatype)
    @utils.multicase(ea=internal.types.integer, target=internal.types.integer, datatype=internal.types.integer)
    @classmethod
    def add_data(cls, ea, target, datatype):
        '''Add a data reference from the address `ea` to `target` using the specified `datatype`.'''
        interface.xref.add_data(ea, target, datatype)
        return target in interface.xref.data_address(ea, descend=True)
    ad = utils.alias(add_data, 'xref')

    @utils.multicase()
    @classmethod
    def rm_code(cls):
        '''Delete _all_ the code references at the current address.'''
        return cls.rm_code(ui.current.address())
    @utils.multicase(ea=internal.types.integer)
    @classmethod
    def rm_code(cls, ea):
        '''Delete _all_ the code references at `ea`.'''
        ea = interface.address.inside(ea)
        [ interface.xref.remove_code(ea, target) for target in interface.xref.code_address(ea, descend=True) ]
        return False if interface.xref.has_code(ea, descend=True) else True
    @utils.multicase(ea=internal.types.integer, target=internal.types.integer)
    @classmethod
    def rm_code(cls, ea, target):
        '''Delete any code references at `ea` that point to address `target`.'''
        ea = interface.address.inside(ea)
        interface.xref.remove_code(ea, target)
        available = {address for address in interface.xref.code_address(ea, descend=True)}
        return target not in available
    rc = utils.alias(rm_code, 'xref')

    @utils.multicase()
    @classmethod
    def rm_data(cls):
        '''Delete _all_ the data references at the current address.'''
        return cls.rm_data(ui.current.address())
    @utils.multicase(ea=internal.types.integer)
    @classmethod
    def rm_data(cls, ea):
        '''Delete _all_ the data references at `ea`.'''
        ea = interface.address.inside(ea)
        [ interface.xref.remove_data(ea, target) for target in interface.xref.data_address(ea, descend=True) ]
        return False if interface.xref.has_data(ea, True) else True
    @utils.multicase(ea=internal.types.integer, target=internal.types.integer)
    @classmethod
    def rm_data(cls, ea, target):
        '''Delete any data references at `ea` that point to address `target`.'''
        ea = interface.address.inside(ea)
        interface.xref.remove_data(ea, target)
        return target not in interface.xref.data_address(ea, descend=True)
    rd = utils.alias(rm_data, 'xref')

    @utils.multicase()
    @classmethod
    def erase(cls):
        '''Clear all code and data references at the current address.'''
        return cls.erase(ui.current.address())
    @utils.multicase(ea=internal.types.integer)
    @classmethod
    def erase(cls, ea):
        '''Clear all code and data references at the address `ea`.'''
        ea = interface.address.inside(ea)
        return all(ok for ok in [cls.rm_code(ea), cls.rm_data(ea)])
    rx = utils.alias(erase, 'xref')

x = xref    # XXX: ns alias

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
        '''Return each of the marked positions within the database as a list composed of tuples packed as `(ea, description)`.'''
        listable = [item for item in cls.iterate()] # make a copy in-case someone is actively modifying it
        return [(ea, comment) for ea, comment in listable]

    @utils.multicase(description=internal.types.string)
    @classmethod
    @utils.string.decorate_arguments('description')
    def new(cls, description):
        '''Create a mark at the current address with the given `description`.'''
        return cls.new(ui.current.address(), description)
    @utils.multicase(ea=internal.types.integer, description=internal.types.string)
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
    @utils.multicase(ea=internal.types.integer)
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
        '''Iterate through the marks within the database.'''
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
    @utils.multicase(ea=internal.types.integer)
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
            return interface.address.head(res, warn=True)

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
            return interface.address.head(res, warn=True)

@utils.multicase()
def mark():
    '''Return the mark at the current address.'''
    _, res = marks.by_address(ui.current.address())
    return res
@utils.multicase(none=internal.types.none)
def mark(none):
    '''Remove the mark at the current address.'''
    return mark(ui.current.address(), None)
@utils.multicase(ea=internal.types.integer)
def mark(ea):
    '''Return the mark at the specified address `ea`.'''
    _, res = marks.by_address(ea)
    return res
@utils.multicase(description=internal.types.string)
@utils.string.decorate_arguments('description')
def mark(description):
    '''Set the mark at the current address to the specified `description`.'''
    return mark(ui.current.address(), description)
@utils.multicase(ea=internal.types.integer, none=internal.types.none)
def mark(ea, none):
    '''Erase the mark at address `ea`.'''
    try:
        internal.tags.address.remove(ea, 'mark', None)
    except E.MissingTagError:
        pass
    DEFCOLOR = 0xffffffff
    interface.address.color(ea, DEFCOLOR)
    return marks.remove(ea)
@utils.multicase(ea=internal.types.integer, description=internal.types.string)
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

    @utils.multicase()
    @classmethod
    def has_prefix(cls):
        '''Return true if there are any extra comments that prefix the item at the current address.'''
        return internal.comment.extra.has_extra(ui.current.address(), idaapi.E_PREV)
    @utils.multicase()
    @classmethod
    def has_suffix(cls):
        '''Return true if there are any extra comments that suffix the item at the current address.'''
        return internal.comment.extra.has_extra(ui.current.address(), idaapi.E_NEXT)

    @utils.multicase(ea=internal.types.integer)
    @classmethod
    def has_prefix(cls, ea):
        '''Return true if there are any extra comments that prefix the item at the address `ea`.'''
        return internal.comment.extra.has_extra(ea, idaapi.E_PREV)
    @utils.multicase(ea=internal.types.integer)
    @classmethod
    def has_suffix(cls, ea):
        '''Return true if there are any extra comments that suffix the item at the address `ea`.'''
        return internal.comment.extra.has_extra(ea, idaapi.E_NEXT)

    @utils.multicase()
    @classmethod
    def prefix(cls):
        '''Return the prefixed comment at the current address.'''
        return internal.comment.extra.get_prefix(ui.current.address())
    @utils.multicase(string=internal.types.string)
    @classmethod
    def prefix(cls, string):
        '''Set the prefixed comment at the current address to the specified `string`.'''
        return internal.comment.extra.set_prefix(ui.current.address(), string)
    @utils.multicase(none=internal.types.none)
    @classmethod
    def prefix(cls, none):
        '''Delete the prefixed comment at the current address.'''
        return internal.comment.extra.delete_prefix(ui.current.address())

    @utils.multicase(ea=internal.types.integer)
    @classmethod
    def prefix(cls, ea):
        '''Return the prefixed comment at address `ea`.'''
        return internal.comment.extra.get_prefix(ea)
    @utils.multicase(ea=internal.types.integer, string=internal.types.string)
    @classmethod
    def prefix(cls, ea, string):
        '''Set the prefixed comment at address `ea` to the specified `string`.'''
        return internal.comment.extra.set_prefix(ea, string)
    @utils.multicase(ea=internal.types.integer, none=internal.types.none)
    @classmethod
    def prefix(cls, ea, none):
        '''Delete the prefixed comment at address `ea`.'''
        return internal.comment.extra.delete_prefix(ea)

    @utils.multicase()
    @classmethod
    def suffix(cls):
        '''Return the suffixed comment at the current address.'''
        return internal.comment.extra.get_suffix(ui.current.address())
    @utils.multicase(string=internal.types.string)
    @classmethod
    def suffix(cls, string):
        '''Set the suffixed comment at the current address to the specified `string`.'''
        return internal.comment.extra.set_suffix(ui.current.address(), string)
    @utils.multicase(none=internal.types.none)
    @classmethod
    def suffix(cls, none):
        '''Delete the suffixed comment at the current address.'''
        return internal.comment.extra.delete_suffix(ui.current.address())
    @utils.multicase(ea=internal.types.integer)
    @classmethod
    def suffix(cls, ea):
        '''Return the suffixed comment at address `ea`.'''
        return internal.comment.extra.get_suffix(ea)
    @utils.multicase(ea=internal.types.integer, string=internal.types.string)
    @classmethod
    def suffix(cls, ea, string):
        '''Set the suffixed comment at address `ea` to the specified `string`.'''
        return internal.comment.extra.set_suffix(ea, string)
    @utils.multicase(ea=internal.types.integer, none=internal.types.none)
    @classmethod
    def suffix(cls, ea, none):
        '''Delete the suffixed comment at address `ea`.'''
        return internal.comment.extra.delete_suffix(ea)

    @utils.multicase(ea=internal.types.integer, count=internal.types.integer)
    @classmethod
    def preinsert(cls, ea, count):
        '''Insert `count` lines in front of the item at address `ea`.'''
        return internal.comment.extra.insert_anterior(ea, count)
    @utils.multicase(ea=internal.types.integer, count=internal.types.integer)
    @classmethod
    def preappend(cls, ea, count):
        '''Append `count` lines in front of the item at address `ea`.'''
        return internal.comment.extra.append_anterior(ea, count)

    @utils.multicase(ea=internal.types.integer, count=internal.types.integer)
    @classmethod
    def postinsert(cls, ea, count):
        '''Insert `count` lines after the item at address `ea`.'''
        return internal.comment.extra.insert_posterior(ea, count)
    @utils.multicase(ea=internal.types.integer, count=internal.types.integer)
    @classmethod
    def postappend(cls, ea, count):
        '''Append `count` lines after the item at address `ea`.'''
        return internal.comment.extra.append_posterior(ea, count)

    @utils.multicase(count=internal.types.integer)
    @classmethod
    def preinsert(cls, count):
        '''Insert `count` lines in front of the item at the current address.'''
        return internal.comment.extra.insert_anterior(ui.current.address(), count)
    @utils.multicase(count=internal.types.integer)
    @classmethod
    def preappend(cls, count):
        '''Append `count` lines in front of the item at the current address.'''
        return internal.comment.extra.append_anterior(ui.current.address(), count)

    @utils.multicase(count=internal.types.integer)
    @classmethod
    def postinsert(cls, count):
        '''Insert `count` lines after the item at the current address.'''
        return internal.comment.extra.insert_posterior(ui.current.address(), count)
    @utils.multicase(count=internal.types.integer)
    @classmethod
    def postappend(cls, count):
        '''Append `count` lines after the item at the current address.'''
        return internal.comment.extra.append_posterior(ui.current.address(), count)

    insert, append = utils.alias(preinsert, 'extra'), utils.alias(preappend, 'extra')
ex = extra  # XXX: ns alias

class set(object):
    """
    This namespace for setting the type of an address within the
    database. This allows one to apply a particular type to a given
    address. This allows one to specify whether a type is a string,
    undefined, code, data, an array, or even a structure.

    This can be used as in the following examples::

        > database.set(ea, type)
        > database.set.unknown(ea)
        > database.set.aligned(ea, alignment=0x10)
        > database.set.string(ea)
        > database.set.structure(ea, structure.by('mystructure'))

    """
    @utils.multicase(info=(internal.types.string, idaapi.tinfo_t))
    def __new__(cls, info):
        '''Set the type information at the current address to `info`.'''
        return cls(ui.current.address(), info)
    @utils.multicase()
    def __new__(cls, type):
        '''Set the type information at the current address to the given pythonic `type`.'''
        return cls(ui.current.address(), type)
    @utils.multicase(ea=internal.types.integer, info=(internal.types.string, idaapi.tinfo_t))
    def __new__(cls, ea, info):
        '''Set the type information at the address `ea` to `info`.'''
        ti, info_s = type(ea, info), "{!s}".format(info) if isinstance(info, idaapi.tinfo_t) else info
        logging.debug(u"{:s}({:#x}, {:s}) : {:s} for address ({:#x}) to \"{:s}\".".format('.'.join([__name__, cls.__name__]), ea, utils.string.repr("{!s}".format(info_s)), "Updated the type (\"{:s}\")".format(utils.string.escape("{!s}".format(ti), '"')) if ti else 'Set the type', ea, utils.string.escape(info_s, '"')))
        return get.type(ea)
    @utils.multicase(ea=internal.types.integer)
    def __new__(cls, ea, type):
        '''Set the type information at the address `ea` to the given pythonic `type`.'''
        FF_ALIGN, FF_STRLIT, FF_STRUCT = map(idaapi.as_uint32, [idaapi.FF_ALIGN, idaapi.FF_STRLIT if hasattr(idaapi, 'FF_STRLIT') else idaapi.FF_ASCI, idaapi.FF_STRUCT if hasattr(idaapi, 'FF_STRUCT') else idaapi.FF_STRU])
        Fcreate_string = idaapi.make_ascii_string if idaapi.__version__ < 7.0 else idaapi.create_strlit

        # Now we have the flags and other stuff, so we need to make sure that we're
        # being called with an address of some sort before applying the type.
        if interface.address.flags(ea, idaapi.MS_CLS) == idaapi.FF_CODE:
            raise E.InvalidTypeOrValueError(u"{:s}{:#x}, {!s}) : Unable to apply the given type ({!s}) to an address ({:#x}) that is defined as code.".format('.'.join([__name__, cls.__name__]), ea, type, type, ea))

        # Last thing to do is to assign the operand information to the address. We're
        # lazy, so we'll try to hand the type off to the correct function for the work.
        flags, tid, nbytes = interface.typemap.resolve(type)
        dtype = flags & interface.typemap.FF_MASKSIZE

        # If the type was resolved to a string, we'll just unpack it to figure
        # out the characteristics of the string, and then call the right function.
        if dtype == FF_STRLIT:
            _, length = type if isinstance(type, internal.types.list) else (type, None)
            width, layout, terminals, encoding = interface.string.unpack(tid)
            return cls.string(ea, width, layout, encoding) if layout else cls.string(ea, width, terminals, encoding)

        elif dtype == FF_STRUCT:
            type, length = type if isinstance(type, internal.types.list) else (type, None)
            return cls.structure(ea, *(type if isinstance(type, tuple) else [type])) if length is None else cls.array(ea, type, length)

        elif dtype == idaapi.FF_ALIGN:
            type, length = type if isinstance(type, internal.types.list) else (type, None)
            return cls.alignment(ea) if type is None else cls.alignment(ea, size=length)

        # If this was a list (array) that we couldn't figure out, then we
        # just unpack it and hand it to the array function to do the work.
        elif isinstance(type, internal.types.list):
            type, length = type
            return cls.array(ea, type, length)

        # Otherwise, we just need to use what we were given to create the data.
        elif not idaapi.create_data(ea, flags, nbytes, tid):
            raise E.DisassemblerError(u"{:s}{:#x}, {!s}) : Unable to apply the given type ({!s}) to the specified address ({:#x}).".format('.'.join([__name__, cls.__name__]), ea, type, type, ea))

        interface.address.update_refinfo(ea, flags)
        return get(ea)
    info = typeinfo = utils.alias(__new__, 'set')

    @utils.multicase()
    @classmethod
    def unknown(cls):
        '''Set the data at the current selection or address to undefined.'''
        selection = ui.current.selection()
        if operator.eq(*(interface.address.head(ea) for ea in selection)):
            return cls.unknown(ui.current.address())
        start, stop = sorted(selection)
        return cls.unknown(start, stop - start)
    @utils.multicase(ea=internal.types.integer)
    @classmethod
    def unknown(cls, ea):
        '''Set the data at address `ea` to undefined.'''
        size = interface.address.size(ea)
        if idaapi.__version__ < 7.0:
            ok = idaapi.do_unknown_range(ea, size, idaapi.DOUNK_SIMPLE)
        else:
            ok = idaapi.del_items(ea, idaapi.DELIT_SIMPLE, size)
        return size if ok and type.unknown(ea, size) else interface.address.size(ea) if type.unknown(ea) else 0
    @utils.multicase(ea=internal.types.integer, size=internal.types.integer)
    @classmethod
    def unknown(cls, ea, size):
        '''Set the data at address `ea` to undefined.'''
        if idaapi.__version__ < 7.0:
            ok = idaapi.do_unknown_range(ea, size, idaapi.DOUNK_SIMPLE)
        else:
            ok = idaapi.del_items(ea, idaapi.DELIT_SIMPLE, size)
        return size if ok and type.unknown(ea, size) else interface.address.size(ea) if type.unknown(ea) else 0
    undef = undefine = undefined = utils.alias(unknown, 'set')

    @utils.multicase()
    @classmethod
    def code(cls):
        '''Set the data at the current address to code.'''
        return cls.code(ui.current.address())
    @utils.multicase(ea=internal.types.integer)
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

    @utils.multicase(size=internal.types.integer)
    @classmethod
    def data(cls, size, **type):
        '''Set the data at the current address to have the specified `size` and `type`.'''
        return cls.data(ui.current.address(), size, type['type']) if 'type' in type else cls.data(ui.current.address(), size, **type)
    @utils.multicase(ea=internal.types.integer, size=internal.types.integer)
    @classmethod
    def data(cls, ea, size):
        '''Set the data at address `ea` to a type that has the specified `size`'''
        lookup = {length : flags for flags, length in interface.decode.length_table.items() if flags != idaapi.as_uint32(idaapi.FF_ALIGN)}

        # If the size doesn't exist, then let the user know that we don't know what to do
        if size not in lookup:
            raise E.InvalidTypeOrValueError(u"{:s}.data({:#x}, {:+d}) : Unable to determine the correct type for the given size ({:+d}) to apply to the specified address ({:#x}).".format('.'.join([__name__, cls.__name__]), ea, size, size, ea))

        # Now we can use the size and type to the right function to apply the determined type.
        flags = lookup[size]
        return cls.data(ea, size, flags)
    @utils.multicase(ea=internal.types.integer, size=internal.types.integer, type=(internal.types.integer, internal.structure.structure_t, idaapi.struc_t))
    @classmethod
    def data(cls, ea, size, type):
        '''Set the data at address `ea` to have the specified `size` using the flags or structure given in `type`.'''
        res = type if isinstance(type, (internal.types.integer, idaapi.struc_t)) else type.ptr

        # Set some constants for anything older than IDA 7.0
        if idaapi.__version__ < 7.0:
            FF_STRUCT = idaapi.FF_STRU

            # Try and fetch some attributes..if we're unable to then we use None
            # as a placeholder so that we know that we need to use the older way
            # that IDA applies structures or alignment
            create_data, create_struct, create_align = idaapi.do_data_ex, getattr(idaapi, 'doStruct', None), getattr(idaapi, 'doAlign', None)

        # Set some constants used for IDA 7.0 and newer
        else:
            FF_STRUCT = idaapi.FF_STRUCT
            create_data, create_struct, create_align = idaapi.create_data, idaapi.create_struct, idaapi.create_align

        # Check if we're supposed to create a struct and if we can actually create one.
        if create_struct and isinstance(res, idaapi.struc_t):
            ok = create_struct(ea, size, res.id)

        # Check if we're supposed to create alignment and if can actually create it.
        elif res == idaapi.FF_ALIGN and create_align:
            ok = create_align(ea, size, 0)

        # Check if we need to use older IDA logic which uses ida_bytes.do_data_ex.
        elif idaapi.__version__ < 7.0:
            ok = create_data(ea, FF_STRUCT if isinstance(res, idaapi.struc_t) else res, size, res.id if isinstance(res, idaapi.struc_t) else idaapi.BADADDR)

        # Anything else is just regular data that we can fall back to ida_bytes.create_data.
        else:
            ok = idaapi.create_data(ea, res, size, idaapi.BADADDR)

        # Return our new size if we were successful.
        return interface.address.size(ea) if ok else 0

    @utils.multicase()
    @classmethod
    def alignment(cls, **alignment):
        '''Set the data at the current address as aligned with the specified `alignment`.'''
        return cls.align(ui.current.address(), **alignment)
    @utils.multicase(ea=internal.types.integer)
    @classmethod
    def alignment(cls, ea, **alignment):
        """Set the data at address `ea` as aligned.

        If `alignment` is specified, then use it as the number of bytes to align the data to.
        If `size` is specified, then align that number of bytes.
        """
        if not type.unknown(ea):
            logging.warning(u"{:s}.set.alignment({:#x}{:s}) : Refusing to align the specified address ({:#x}) as it has already been defined.".format('.'.join([__name__, cls.__name__]), ea, u", {:s}".format(utils.string.kwargs(alignment)) if alignment else '', ea))  # XXX: define a custom warning
            return 0

        # alignment can only be determined if there's an actual size, so
        # we'll need some way to calculate the size if we weren't given one.
        def calculate_size(ea):

            # if the address is initialized, then we'll figure it out by
            # looking for bytes that repeat.
            if type.initialized(ea):
                size, by = 0, interface.address.read(ea, 1)
                while interface.address.read(ea + size, 1) == by:
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
        return interface.address.size(ea)
    align = aligned = utils.alias(alignment, 'set')

    @utils.multicase()
    @classmethod
    def string(cls, **strtype):
        '''Set the data at the current selection or address to a string with the specified `strtype` and `encoding`.'''
        address, selection = ui.current.address(), ui.current.selection()
        if 'length' in strtype or operator.eq(*(interface.address.head(ea) for ea in selection)):
            return cls.string(address, **strtype)
        return cls.string(selection, **strtype)
    @utils.multicase(bounds=interface.bounds_t)
    @classmethod
    def string(cls, bounds, **strtype):
        '''Set the data within the provided `bounds` to a string with the specified `strtype` and `encoding`.'''
        default = interface.string.default()
        width, layout, terminals, encoding = interface.string.unpack(default)

        # If we received any explicit string type, then update our defaults.
        if any(item in strtype for item in ['strtype', 'type']):
            res = builtins.next(strtype[item] for item in ['strtype', 'type'] if item in strtype)
            width, layout = res if isinstance(res, internal.types.ordered) else (res, 0)

        # If we received a character width, then we can also use it.
        elif 'width' in strtype:
            width = strtype['width']

        # We were given an exact bounds for the string which means that we're
        # being asked to do exactly what the user wants and we can skip ahead
        # to the actual function that is responsible for making the string.
        return cls.string(bounds, width, layout, strtype.get('encoding', encoding))
    @utils.multicase(ea=internal.types.integer)
    @classmethod
    def string(cls, ea, **strtype):
        """Set the data at address `ea` to a string with the specified `strtype` and `encoding`.

        The integer or tuple `strtype` contains the character width and the length prefix (or desired terminator) for the bytes representing the string.
        """
        default = interface.string.default()
        width, layout, terminals, encoding = interface.string.unpack(default)

        # First check if we received any explicit string type information.
        if any(item in strtype for item in ['strtype', 'type']):
            res = builtins.next(strtype[item] for item in ['strtype', 'type'] if item in strtype)
            width, layout = res if isinstance(res, internal.types.ordered) else (res, 0)

        # If we received a character width, then we can use it as-is.
        elif 'width' in strtype:
            width = strtype['width']

        # Next check if we were given terminal chars as the layout. If so, then
        # our layout should be assigned to our terminals with its new value as 0.
        layout, terminals = (0, terminals) if isinstance(layout, internal.types.bytes) else (layout, terminals)

        # If we were given an explicit string length, then we need to adjust our
        # boundaries to include the layout size when making the string.
        if 'length' in strtype:
            bounds = interface.bounds_t(ea, ea + layout + width * strtype['length'])
            return cls.string(bounds, width, layout, strtype.get('encoding', encoding))
        return cls.string(ea, width, layout if layout > 0 else terminals, strtype.get('encoding', encoding))

    # The following implementations are responsible for figuring out the correct
    # string length before handing their parameters to the correct function.

    @utils.multicase(ea=internal.types.integer, width=internal.types.integer, length=internal.types.integer, encoding=(internal.types.integer, internal.types.string, internal.types.none))
    @classmethod
    def string(cls, ea, width, length, encoding):
        '''Set data at the address `ea` to a string of the given `encoding` using the provided character `width` and `length` prefix size.'''

        # If we were given a length of 0, then use the default string type
        # to figure out what our terminal characters should be.
        if length == 0:
            default = interface.string.default()
            _, _, terminals, _ = interface.string.unpack(default)
            return cls.string(ea, width, terminals, encoding)

        # Now we can read the length prefix and use it to calculate the boundaries
        # of our string. Since we're setting it, we start at the length prefix.
        bounds = interface.bounds_t(ea, ea + length + width * get.unsigned(ea, length))
        return cls.string(bounds, width, length, encoding)
    @utils.multicase(ea=internal.types.integer, width=internal.types.integer, terminal=internal.types.bytes, encoding=(internal.types.integer, internal.types.string, internal.types.none))
    @classmethod
    def string(cls, ea, width, terminal, encoding):
        '''Set data at the address `ea` to a string terminated by `terminal` using the given `encoding` and character `width`.'''
        default = interface.string.default()
        _, _, default, _ = interface.string.unpack(default)

        # Tests used to terminate reading if our current address ends up being out
        # of bounds or is pointing at an uninitialized value that we can't read.
        _, bottom = segment.bounds(ea)
        Fwithin_bounds = utils.fcompose(functools.partial(operator.sub, bottom), functools.partial(functools.partial, operator.gt))
        Finitialized = utils.fcompose(utils.frpartial(interface.address.flags, idaapi.FF_IVL), operator.truth)

        # Figure out our terminal characters that we'll use for the string length.
        sentinel = bytearray(itertools.islice(itertools.chain(terminal or b'', default * width), width))
        Fis_terminator = utils.fcompose(functools.partial(read, size=width), functools.partial(operator.eq, builtins.bytes(sentinel)))

        # Now we have everything we need to read bytes from the database until
        # we encounter our terminator characters. Start at the address we were
        # given and read "width" bytes until we've stopped or can't proceed.
        iterable = itertools.count(ea, width)
        takewhile = utils.fcompose(utils.fmap(Fwithin_bounds(width), Finitialized, utils.fnot(Fis_terminator)), all)
        right = width + functools.reduce(utils.fpack(operator.itemgetter(1)), itertools.takewhile(takewhile, iterable), ea)

        # Finally that gives us the actual string size but without the terminator
        # characters.. so, we need to add the terminal character size and then we
        # can dispatch to the right function to create the desired string.
        bounds = interface.bounds_t(ea, right + width)
        return cls.string(bounds, width, 0, encoding)

    # Each of the implementations that follow are the only ones that are actually
    # responsible for marking the string within the database. This implies that
    # everything prior is just sugar that figures out the parameters to use them.

    @utils.multicase(bounds=interface.bounds_t, width=internal.types.integer, length=internal.types.integer, encoding=internal.types.string)
    @classmethod
    def string(cls, bounds, width, length, encoding):
        '''Set data at the specified `bounds` to a string of the given `encoding` with the provided character `width` and `length` prefix size.'''
        bounds = interface.bounds_t(*bounds)

        # If the codec doesn't exist, then try and add it to the database.
        if interface.string.codec(width, encoding) is None:
            raise E.UnsupportedCapability(u"{:s}.string({:s}, {:d}, {:d}, {!r}) : The requested string encoding ({:s}) is unavailable.".format('.'.join([__name__, cls.__name__]), bounds, width, length, encoding, utils.string.escape(encoding, '"')))

        # Grab its index and then recurse with the correct encoding index.
        index = interface.string.encoding(encoding)
        if index < 0:
            raise E.ItemNotFoundError(u"{:s}.string({:s}, {:d}, {:d}, {!r}) : The requested string encoding ({:s}) could not be found in the database.".format('.'.join([__name__, cls.__name__]), bounds, width, length, encoding, utils.string.escape(encoding, '"')))
        return cls.string(bounds, width, length, index)
    @utils.multicase(bounds=interface.bounds_t, width=internal.types.integer, length=internal.types.integer, encoding=(internal.types.integer, internal.types.none))
    @classmethod
    def string(cls, bounds, width, length, encoding):
        '''Set data at the specified `bounds` to a string of the given `encoding` with the provided character `width` and `length` prefix size.'''
        Fcreate_string = idaapi.make_ascii_string if idaapi.__version__ < 7.0 else idaapi.create_strlit

        # First we need the string size from the boundaries we we were given.
        ea, _ = sorted(bounds)
        bounds, size = interface.bounds_t(*bounds), operator.sub(*reversed(sorted(bounds)))

        # Next verify that the parameters we were given are for a valid string type.
        if not interface.string.check(width, length):
            raise E.UnsupportedCapability(u"{:s}.string({:s}, {:d}, {:d}, {:d}) : Unable to create a string with an unsupported character width ({:d}) and length prefix ({:d}).".format('.'.join([__name__, cls.__name__]), bounds, width, length, encoding, width, length))
        res = interface.string.pack(width, length, b'\0\0', encoding)

        # Before we actually start to undefine anything, we need to make sure that the
        # length prefix size fits within the suggestdd boundaries so that the user knows.
        if size < length:
            raise E.InvalidTypeOrValueError(u"{:s}.string({:s}, {:d}, {:d}, {:d}) : The size of the length prefix ({:d}) is larger than the maximum size ({:d}) of the requested boundaries ({:s}).".format('.'.join([__name__, cls.__name__]), bounds, width, length, encoding, length, size, bounds))

        # Next, check that the number of bytes after the length prefix is divisible
        # by the string character width and adjust the total size if it isn't.
        elif (size - length) % width:
            characters = max(0, size - length)
            adjustment = characters % -width
            fmt_characters = "{:d}{:+d}".format(length, characters) if length else "{:d}".format(characters)
            fmt_new = "{:d}{:+d}".format(length, characters + adjustment) if length else "{:d}".format(characters + adjustment)
            logging.warning(u"{:s}.string({:s}, {:d}, {:d}, {:d}) : The chosen boundaries ({:s}) have a size ({:s}) that is not divisible by the character width ({:d}) and will be adjusted by {:+d} byte{:s} to result in the size of {:s} byte{:s}.".format('.'.join([__name__, cls.__name__]), bounds, width, length, encoding, bounds, fmt_characters, width, adjustment, '' if abs(adjustment) == 1 else 's', fmt_new, '' if characters + adjustment == 1 else 's'))
            size = length + characters + adjustment

        # If the data at the starting address is defined, then we need to undefine it.
        cb = size if type.unknown(ea) else cls.unknown(ea, size)
        if cb != size:
            raise E.DisassemblerError(u"{:s}.string({:s}, {:d}, {:d}, {:d}) : Unable to undefine {:d} bytes at the requested address ({:#x}) for the string.".format('.'.join([__name__, cls.__name__]), bounds, width, length, encoding, size, ea))

        # Now we can make a string at the undefined address and decode the string
        # that we just made if we were successful. Otherwise, we bail (of course).
        if Fcreate_string(ea, size, res):
            bounds = interface.bounds_t(ea + length, ea + length + size)
            return get.string(bounds, width, encoding)
        raise E.DisassemblerError(u"{:s}.string({:s}, {:d}, {:d}, {:d}) : Unable to define the specified address ({:#x}) as a string of the requested strtype {:#0{:d}x}.".format('.'.join([__name__, cls.__name__]), bounds, width, length, encoding, ea, res, 2 + 8))

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
        @utils.multicase(ea=internal.types.integer)
        def __new__(cls, ea):
            '''Set the data at address `ea` to an integer of a type determined by its size.'''
            res = interface.address.size(ea)
            return cls(ea, res)
        @utils.multicase(ea=internal.types.integer, size=internal.types.integer)
        def __new__(cls, ea, size):
            '''Set the data at the address `ea` to an integer of the specified `size`.'''
            res = set.unknown(ea, size)
            if not type.unknown(ea, size) or res < size:
                raise E.DisassemblerError(u"{:s}({:#x}, {:d}) : Unable to undefine {:d} byte{:s} for the integer.".format('.'.join([__name__, 'set', cls.__name__]), ea, size, '' if size == 1 else 's'))

            if not set.data(ea, size):
                raise E.DisassemblerError(u"{:s}({:#x}, {:d}) : Unable to set the specified address to an integer ({:d}-bit).".format('.'.join([__name__, 'set', cls.__name__]), ea, size, 8 * size))
            return get.signed(ea, size) if interface.address.flags(ea, idaapi.FF_SIGN) else get.unsigned(ea, size)

        @utils.multicase()
        @classmethod
        def uint8_t(cls):
            '''Set the data at the current address to a uint8_t.'''
            return cls.uint8_t(ui.current.address())
        @utils.multicase(ea=internal.types.integer)
        @classmethod
        def uint8_t(cls, ea):
            '''Set the data at address `ea` to a uint8_t.'''
            res = set.unknown(ea, 1)
            if not type.unknown(ea, 1) or res < 1:
                raise E.DisassemblerError(u"{:s}.uint8_t({:#x}) : Unable to undefine {:d} byte for the integer.".format('.'.join([__name__, 'set', cls.__name__]), ea, 1))

            # Apply our data type after undefining it
            if not set.data(ea, res, type=idaapi.FF_BYTE):
                raise E.DisassemblerError(u"{:s}.uint8_t({:#x}) : Unable to set the specified address to an integer ({:d}-bit).".format('.'.join([__name__, 'set', cls.__name__]), ea, 8 * res))

            # Check if we need to flip the sign flag, and do it if necessary
            if interface.address.flags(ea, idaapi.FF_SIGN):
                idaapi.toggle_sign(ea, 0)

            # Return our new size
            return get.unsigned(ea, res)
        @utils.multicase()
        @classmethod
        def sint8_t(cls):
            '''Set the data at the current address to a sint8_t.'''
            return cls.sint8_t(ui.current.address())
        @utils.multicase(ea=internal.types.integer)
        @classmethod
        def sint8_t(cls, ea):
            '''Set the data at address `ea` to a sint8_t.'''
            res = set.unknown(ea, 1)
            if not type.unknown(ea, 1) or res < 1:
                raise E.DisassemblerError(u"{:s}.sint8_t({:#x}) : Unable to undefine {:d} byte for the integer.".format('.'.join([__name__, 'set', cls.__name__]), ea, 1))

            # Apply our data type after undefining it
            if not set.data(ea, res, type=idaapi.FF_BYTE):
                raise E.DisassemblerError(u"{:s}.sint8_t({:#x}) : Unable to set the specified address to an integer ({:d}-bit).".format('.'.join([__name__, 'set', cls.__name__]), ea, 8 * res))

            # Check if we need to flip the sign flag, and do it if necessary
            if not interface.address.flags(ea, idaapi.FF_SIGN):
                idaapi.toggle_sign(ea, 0)

            # Return our new size
            return get.signed(ea, res)
        byte = utils.alias(uint8_t, 'set.integer')

        @utils.multicase()
        @classmethod
        def uint16_t(cls):
            '''Set the data at the current address to a uint16_t.'''
            return cls.uint16_t(ui.current.address())
        @utils.multicase(ea=internal.types.integer)
        @classmethod
        def uint16_t(cls, ea):
            '''Set the data at address `ea` to a uint16_t.'''
            res = set.unknown(ea, 2)
            if not type.unknown(ea, 2) or res < 2:
                raise E.DisassemblerError(u"{:s}.uint16_t({:#x}) : Unable to undefine {:d} bytes for the integer.".format('.'.join([__name__, 'set', cls.__name__]), ea, 2))

            # Apply our data type after undefining it
            if not set.data(ea, res, type=idaapi.FF_WORD):
                raise E.DisassemblerError(u"{:s}.uint16_t({:#x}) : Unable to set the specified address to an integer ({:d}-bit).".format('.'.join([__name__, 'set', cls.__name__]), ea, 8 * res))

            # Check if we need to flip the sign flag, and do it if necessary
            if interface.address.flags(ea, idaapi.FF_SIGN):
                idaapi.toggle_sign(ea, 0)

            # Return our new size
            return get.unsigned(ea, res)
        @utils.multicase()
        @classmethod
        def sint16_t(cls):
            '''Set the data at the current address to a sint16_t.'''
            return cls.sint16_t(ui.current.address())
        @utils.multicase(ea=internal.types.integer)
        @classmethod
        def sint16_t(cls, ea):
            '''Set the data at address `ea` to a sint16_t.'''
            res = set.unknown(ea, 2)
            if not type.unknown(ea, 2) or res < 2:
                raise E.DisassemblerError(u"{:s}.sint16_t({:#x}) : Unable to undefine {:d} bytes for the integer.".format('.'.join([__name__, 'set', cls.__name__]), ea, 2))

            # Apply our data type after undefining it
            if not set.data(ea, res, type=idaapi.FF_WORD):
                raise E.DisassemblerError(u"{:s}.sint16_t({:#x}) : Unable to set the specfied address to an integer ({:d}-bit).".format('.'.join([__name__, 'set', cls.__name__]), ea, 8 * res))

            # Check if we need to flip the sign flag, and do it if necessary
            if not interface.address.flags(ea, idaapi.FF_SIGN):
                idaapi.toggle_sign(ea, 0)

            # Return our new size
            return get.signed(ea, res)
        word = utils.alias(uint16_t, 'set.integer')

        @utils.multicase()
        @classmethod
        def uint32_t(cls):
            '''Set the data at the current address to a uint32_t.'''
            return cls.uint32_t(ui.current.address())
        @utils.multicase(ea=internal.types.integer)
        @classmethod
        def uint32_t(cls, ea):
            '''Set the data at address `ea` to a uint32_t.'''
            FF_DWORD = idaapi.FF_DWORD if hasattr(idaapi, 'FF_DWORD') else idaapi.FF_DWRD

            # Undefine the data at the specified address
            res = set.unknown(ea, 4)
            if not type.unknown(ea, 4) or res < 4:
                raise E.DisassemblerError(u"{:s}.uint32_t({:#x}) : Unable to undefine {:d} bytes for the integer.".format('.'.join([__name__, 'set', cls.__name__]), ea, 4))

            # Apply our new data type after undefining it
            if not set.data(ea, res, type=FF_DWORD):
                raise E.DisassemblerError(u"{:s}.uint32_t({:#x}) : Unable to set the specified address to an integer ({:d}-bit).".format('.'.join([__name__, 'set', cls.__name__]), ea, 8 * res))

            # Check if we need to flip the sign flag, and do it if necessary
            if interface.address.flags(ea, idaapi.FF_SIGN):
                idaapi.toggle_sign(ea, 0)

            # Now we can return our new size
            return get.unsigned(ea, res)
        @utils.multicase()
        @classmethod
        def sint32_t(cls):
            '''Set the data at the current address to a sint32_t.'''
            return cls.sint32_t(ui.current.address())
        @utils.multicase(ea=internal.types.integer)
        @classmethod
        def sint32_t(cls, ea):
            '''Set the data at address `ea` to a sint32_t.'''
            FF_DWORD = idaapi.FF_DWORD if hasattr(idaapi, 'FF_DWORD') else idaapi.FF_DWRD

            # Undefine the data at the specified address
            res = set.unknown(ea, 4)
            if not type.unknown(ea, 4) or res < 4:
                raise E.DisassemblerError(u"{:s}.uint32_t({:#x}) : Unable to undefine {:d} bytes for the integer.".format('.'.join([__name__, 'set', cls.__name__]), ea, 4))

            # Apply our new data type after undefining it
            if not set.data(ea, res, type=FF_DWORD):
                raise E.DisassemblerError(u"{:s}.uint32_t({:#x}) : Unable to set the specified address to an integer ({:d}-bit).".format('.'.join([__name__, 'set', cls.__name__]), ea, 8 * res))

            # Check if we need to flip the sign flag, and do it if necessary
            if not interface.address.flags(ea, idaapi.FF_SIGN):
                idaapi.toggle_sign(ea, 0)

            # Now we can return our new size
            return get.signed(ea, res)
        dword = utils.alias(uint32_t, 'set.integer')

        @utils.multicase()
        @classmethod
        def uint64_t(cls):
            '''Set the data at the current address to a uint64_t.'''
            return cls.uint64_t(ui.current.address())
        @utils.multicase(ea=internal.types.integer)
        @classmethod
        def uint64_t(cls, ea):
            '''Set the data at address `ea` to a uint64_t.'''
            FF_QWORD = idaapi.FF_QWORD if hasattr(idaapi, 'FF_QWORD') else idaapi.FF_QWRD

            # Undefine the data at the specified address
            res = set.unknown(ea, 8)
            if not type.unknown(ea, 8) or res < 8:
                raise E.DisassemblerError(u"{:s}.uint64_t({:#x}) : Unable to undefine {:d} bytes for the integer.".format('.'.join([__name__, 'set', cls.__name__]), ea, 8))

            # Apply our new data type after undefining it
            if not set.data(ea, res, type=FF_QWORD):
                raise E.DisassemblerError(u"{:s}.uint64_t({:#x}) : Unable to set the specified address to an integer ({:d}-bit).".format('.'.join([__name__, 'set', cls.__name__]), ea, 8 * res))

            # Check if we need to flip the sign flag, and do it if necessary
            if interface.address.flags(ea, idaapi.FF_SIGN):
                idaapi.toggle_sign(ea, 0)

            # Now we can return our new value since everything worked
            return get.unsigned(ea, res)
        @utils.multicase()
        @classmethod
        def sint64_t(cls):
            '''Set the data at the current address to a sint64_t.'''
            return cls.sint64_t(ui.current.address())
        @utils.multicase(ea=internal.types.integer)
        @classmethod
        def sint64_t(cls, ea):
            '''Set the data at address `ea` to a sint64_t.'''
            FF_QWORD = idaapi.FF_QWORD if hasattr(idaapi, 'FF_QWORD') else idaapi.FF_QWRD

            # Undefine the data at the specified address
            res = set.unknown(ea, 8)
            if not type.unknown(ea, 8) or res < 8:
                raise E.DisassemblerError(u"{:s}.uint64_t({:#x}) : Unable to undefine {:d} bytes for the integer.".format('.'.join([__name__, 'set', cls.__name__]), ea, 8))

            # Apply our new data type after undefining it
            if not set.data(ea, res, type=FF_QWORD):
                raise E.DisassemblerError(u"{:s}.uint64_t({:#x}) : Unable to set the specified address to an integer ({:d}-bit).".format('.'.join([__name__, 'set', cls.__name__]), ea, 8 * res))

            # Check if we need to flip the sign flag, and do it if necessary
            if not interface.address.flags(ea, idaapi.FF_SIGN):
                idaapi.toggle_sign(ea, 0)

            # Now we can return our new value since everything worked
            return get.signed(ea, res)
        qword = utils.alias(uint64_t, 'set.integer')

        @utils.multicase()
        @classmethod
        def uint128_t(cls):
            '''Set the data at the current address to an uint128_t.'''
            return cls.uint128_t(ui.current.address())
        @utils.multicase(ea=internal.types.integer)
        @classmethod
        def uint128_t(cls, ea):
            '''Set the data at address `ea` to an uint128_t.'''
            FF_OWORD = idaapi.FF_OWORD if hasattr(idaapi, 'FF_OWORD') else idaapi.FF_OWRD

            # Undefine the data at the specified address
            res = set.unknown(ea, 16)
            if not type.unknown(ea, 16) or res < 16:
                raise E.DisassemblerError(u"{:s}.uint128_t({:#x}) : Unable to undefine {:d} bytes for the integer.".format('.'.join([__name__, 'set', cls.__name__]), ea, 16))

            # Apply our new data type after undefining it
            if not set.data(ea, res, type=FF_OWORD):
                raise E.DisassemblerError(u"{:s}.uint128_t({:#x}) : Unable to set the specified address to an integer ({:d}-bit).".format('.'.join([__name__, 'set', cls.__name__]), ea, 8 * res))

            # Check if we need to flip the sign flag, and do it if necessary
            if interface.address.flags(ea, idaapi.FF_SIGN):
                idaapi.toggle_sign(ea, 0)

            # Now we can return our new value if we succeeded
            return get.signed(ea, res)
        @utils.multicase()
        @classmethod
        def sint128_t(cls):
            '''Set the data at the current address to a sint128_t.'''
            return cls.sint128_t(ui.current.address())
        @utils.multicase(ea=internal.types.integer)
        @classmethod
        def sint128_t(cls, ea):
            '''Set the data at address `ea` to an sint128_t.'''
            FF_OWORD = idaapi.FF_OWORD if hasattr(idaapi, 'FF_OWORD') else idaapi.FF_OWRD

            # Undefine the data at the specified address
            res = set.unknown(ea, 16)
            if not type.unknown(ea, 16) or res < 16:
                raise E.DisassemblerError(u"{:s}.uint128_t({:#x}) : Unable to undefine {:d} bytes for the integer.".format('.'.join([__name__, 'set', cls.__name__]), ea, 16))

            # Apply our new data type after undefining it
            if not set.data(ea, res, type=FF_OWORD):
                raise E.DisassemblerError(u"{:s}.uint128_t({:#x}) : Unable to set the specified address to an integer ({:d}-bit).".format('.'.join([__name__, 'set', cls.__name__]), ea, 8 * res))

            # Check if we need to flip the sign flag, and do it if necessary
            if not interface.address.flags(ea, idaapi.FF_SIGN):
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
        @utils.multicase(ea=internal.types.integer)
        def __new__(cls, ea):
            '''Sets the data at address `ea` to an IEEE-754 floating-point number based on its size.'''
            size = interface.address.size(ea)
            if size < 4 and type.unknown(ea, 4):
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
        @utils.multicase(ea=internal.types.integer)
        @classmethod
        def single(cls, ea):
            '''Set the data at address `ea` to an IEEE-754 single.'''
            res = set.unknown(ea, 4)
            if not type.unknown(ea, 4) or res < 4:
                raise E.DisassemblerError(u"{:s}.single({:#x}) : Unable to undefine {:d} bytes for the float.".format('.'.join([__name__, 'set', cls.__name__]), ea, 4))

            # Apply our data type after undefining it
            if not set.data(ea, res, type=idaapi.FF_FLOAT & 0xf0000000):
                raise E.DisassemblerError(u"{:s}.single({:#x}) : Unable to assign a single to the specified address.".format('.'.join([__name__, 'set', cls.__name__]), ea))

            # Return our new value
            return get.float.single(ea)

        @utils.multicase()
        @classmethod
        def double(cls):
            '''Set the data at the current address to an IEEE-754 double'''
            return cls.double(ui.current.address())
        @utils.multicase(ea=internal.types.integer)
        @classmethod
        def double(cls, ea):
            '''Set the data at address `ea` to an IEEE-754 double.'''
            res = set.unknown(ea, 8)
            if not type.unknown(ea, 8) or res < 8:
                raise E.DisassemblerError(u"{:s}.double({:#x}) : Unable to undefine {:d} bytes for the float.".format('.'.join([__name__, 'set', cls.__name__]), ea, 8))

            # Apply our data type after undefining it
            if not set.data(ea, res, type=idaapi.FF_DOUBLE & 0xf0000000):
                raise E.DisassemblerError(u"{:s}.double({:#x}) : Unable to assign a double to the specified address.".format('.'.join([__name__, 'set', cls.__name__]), ea))

            # Return our new value
            return get.float.double(ea)
    f = float   # XXX: ns alias

    @utils.multicase(structure=(idaapi.struc_t, internal.structure.structure_t))
    @classmethod
    def structure(cls, structure):
        '''Set the data at the current address to the specified `structure`.'''
        return cls.structure(ui.current.address(), structure)
    @utils.multicase(name=internal.types.string)
    @classmethod
    @utils.string.decorate_arguments('name', 'suffix')
    def structure(cls, name, *suffix):
        '''Set the data at the current address to the structure with the given `name`.'''
        return cls.structure(ui.current.address(), name, *suffix)
    @utils.multicase(ea=internal.types.integer, structure=(idaapi.struc_t, internal.structure.structure_t))
    @classmethod
    def structure(cls, ea, structure):
        '''Set the data at address `ea` to the specified `structure`.'''
        sptr = structure if isinstance(structure, idaapi.struc_t) else structure.ptr
        return cls.structure(ea, sptr, idaapi.get_struc_size(sptr))
    @utils.multicase(ea=internal.types.integer, structure=(idaapi.struc_t, internal.structure.structure_t), size=internal.types.integer)
    @classmethod
    def structure(cls, ea, structure, size):
        '''Set the data at address `ea` to the specified `structure` of `size` bytes.'''
        sptr = structure if isinstance(structure, idaapi.struc_t) else structure.ptr
        result = cls.data(ea, size, type=sptr)
        if not result:
            raise E.DisassemblerError(u"{:s}.structure({:#x}, {:#x}, {:+d}) : Unable to apply the given structure ({:#x}) with size ({:+d}) to the specified address ({:#x}).".format('.'.join([__name__, cls.__name__]), ea, sptr.id, size, sptr.id, size, ea))
        return get.structure(ea, sptr, result)
    @utils.multicase(ea=internal.types.integer, name=internal.types.string)
    @classmethod
    @utils.string.decorate_arguments('name', 'suffix')
    def structure(cls, ea, name, *suffix):
        '''Set the data at address `ea` to the structure with the given `name`.'''
        st = _structure.by_name(name, *suffix, offset=ea)
        return cls.structure(ea, st)
    @utils.multicase(ea=internal.types.integer, identifier=internal.types.integer)
    @classmethod
    def structure(cls, ea, identifier):
        '''Set the data at address `ea` to the structure that has the specified `identifier`.'''
        st = internal.structure.new(identifier, ea)
        return cls.structure(ea, st)
    struc = struct = utils.alias(structure, 'set')

    @utils.multicase()
    @classmethod
    def array(cls):
        '''Set the data at the current selection to an array of the type at the current address.'''
        address, selection = ui.current.address(), ui.current.selection()

        # If we were given an explicit address, then we just chain to the right case.
        if operator.eq(*(interface.address.head(ea) for ea in selection)):
            return cls.array(address)

        # Otherwise we unpack the selection, grab the type, and use them to
        # calculate the new length so that we can warn the user if necessary.
        start, stop = sorted(selection)
        original_type, original_length = type.array(start)

        _, _, nbytes = interface.typemap.resolve(original_type)
        result = math.ceil((stop - start) / nbytes)

        # Now we warn if the user is asking us to change the length in some way.
        length = math.trunc(result)
        if original_length > 1 and length != original_length:
            logging.warning(u"{:s}.array() : Modifying the number of elements ({:d}) for the array at the current selection ({:#x}<>{:#x}) to {:d}.".format('.'.join([__name__, cls.__name__]), original_length, start, stop, length))
        return cls.array(start, original_type, length)
    @utils.multicase(ea=internal.types.integer)
    @classmethod
    def array(cls, ea):
        '''Set the data at the address `ea` to an array by scanning for continguous types and values.'''
        original_type, original_length = type.array(ea)

        # If the array already has a length, then there really isn't anything to do without
        # explicitly changing the already defined array.. So in essence, we're done here.
        if original_length > 1:
            return get.array(ea, type=original_type, length=original_length)
        return cls.array(ea, original_type)
    @utils.multicase()
    @classmethod
    def array(cls, type, **length):
        '''Set the data at the current address to an array of the specified `type` using the length determined from the current selection if `length` is not specified.'''
        if 'length' in length and isinstance(type, internal.types.list):
            ttype, tlength = type
            if tlength != length['length']:
                raise E.InvalidParameterError(u"{:s}.array({!r}{:s}) : Multiple values for the array length were passed in the type ({:d}) and the parameter ({:d}).".format('.'.join([__name__, cls.__name__]), ttype, ", {:s}".format(utils.string.kwargs(length)) if length else '', tlength, length['length']))
            return cls.array(ui.current.address(), ttype, tlength)
        elif isinstance(type, internal.types.list):
            type, length = type
            return cls.array(ui.current.address(), type, length)
        elif 'length' in length:
            return cls.array(ui.current.address(), type, length['length'])

        # If no length was specified, then we'll check the current selection.
        selection = ui.current.selection()
        if operator.eq(*(interface.address.head(ea) for ea in selection)):
            return cls.array(ui.current.address(), type)
        start, stop = selection
        return cls.array(interface.bounds_t(start, address.next(stop)), type)
    @utils.multicase(ea=internal.types.integer)
    @classmethod
    def array(cls, ea, type):
        '''Set the data at the address `ea` to an array of the given `type`.'''
        type, length = type if isinstance(type, internal.types.list) else (type, 0)

        # If we were already given a length, then we can simply comply.
        if length > 0:
            return cls.array(ea, type, length)

        # Grab our desired size and the original type so that we can determine if
        # we're going to be updating or changing the array.
        info, size, flags = idaapi.opinfo_t(), interface.typemap.size(type), interface.address.flags(ea)
        addresses = [ea + address for address in builtins.range(size)]

        # XXX: We could probably use `can_define_item(ea_t, asize_t, flags_t)`, but I'm not sure
        #      how it works and if it can be used to scan for the maximum possible size for a type.
        ok = idaapi.get_opinfo(ea, idaapi.OPND_ALL, flags, info) if idaapi.__version__ < 7.0 else idaapi.get_opinfo(info, ea, idaapi.OPND_ALL, flags)
        tid = info.tid if ok else idaapi.BADADDR
        original_type = interface.typemap.dissolve(flags, tid, interface.address.size(ea))
        type_being_changed = flags & idaapi.MS_CLS == idaapi.FF_DATA and original_type != type

        # Now we need to create our conditions to scan from our start address until we encounter
        # a boundary that is worth stopping at (label, reference, invalid ^ valid).
        while_conditions = {}
        while_conditions[idaapi.MS_CLS] = functools.partial(operator.contains, {idaapi.FF_UNK})
        while_conditions[idaapi.DT_TYPE] = functools.partial(operator.eq, 0)
        while_conditions[idaapi.FF_TAIL] = functools.partial(operator.eq, 0)

        has_value = flags & idaapi.FF_IVL
        while_conditions[idaapi.FF_IVL] = functools.partial(operator.contains, {idaapi.FF_IVL if has_value else 0})

        conditions = functools.reduce(operator.or_, {idaapi.FF_REF, idaapi.FF_NAME, idaapi.FF_LABL})
        while_conditions[idaapi.MS_COMM] = utils.fcompose(functools.partial(operator.and_, conditions), operator.not_)

        # First check if the type at the starting address is defined and verify that the
        # size matches. If so, then we need to skip past the first element when scanning.
        iterable = ((address, interface.address.flags(address, idaapi.MS_CLS|idaapi.FF_TAIL)) for address in addresses[:1])
        items = [address for address, flag in iterable if flag & idaapi.MS_CLS == idaapi.FF_DATA]
        items.extend(address for address in addresses[1:] if interface.address.flags(address, idaapi.FF_TAIL))
        base = 1 if len(items) == size and original_type == type else 0

        # Now we can use an iterator to scan for bytes that we can overwrite. However, we
        # need to adjust this iterator in case we need to skip the first byte due to a label.
        Fwhile = utils.fcompose(interface.address.flags, utils.fmap(*itertools.starmap(utils.fcompose, ([functools.partial(operator.and_, mask), condition] for mask, condition in while_conditions.items()))), all)
        counter = itertools.count(ea + base * size) if Fwhile(ea) or base else itertools.count(ea)
        iterable = counter if flags & idaapi.FF_TAIL or type_being_changed else itertools.chain([1 + builtins.next(counter)], counter)
        scanner = itertools.takewhile(Fwhile, iterable)

        # Finally we can just take our sum of elements, add the base, and then hand it off
        # to the correct case for setting the array if the length is defined.
        length = base + sum(1 for address in zip(*[scanner] * size))
        if length > 0:
            return cls.array(ea, type, length)

        # Otherwise to create this array, we'd have to explicitly change its type. Since this case
        # actually guesses that length, we don't want to explicitly destroy anything. If the user
        # really wants to, though, they can specify the length themselves to forcefully overwrite it.
        raise E.InvalidParameterError(u"{:s}.array({!s}, {!r}) : Refusing to change the array at address ({:#x}) due it being of a different type {!r}.".format('.'.join([__name__, cls.__name__]), ea, type, ea, original_type))
    @utils.multicase(bounds=interface.bounds_t)
    @classmethod
    def array(cls, bounds, type):
        '''Set the data at the provided `bounds` to an array of the given `type`.'''
        if isinstance(type, internal.types.list):
            raise E.InvalidParameterError(u"{:s}.array({!s}, {!r}) : Unable to define the provided boundary ({!r}) as an array of the given element type ({!s}).".format('.'.join([__name__, cls.__name__]), interface.bounds_t(*bounds), type, bounds, type))
        start, stop = sorted(bounds)

        # Calculate the size of the type that we were given.
        _, _, nbytes = interface.typemap.resolve(type)
        length = operator.sub(*reversed(sorted(bounds)))

        # Now we can use it to calculate the length and apply it.
        res = math.ceil(length / nbytes)
        return cls.array(start, type, math.trunc(res))
    @utils.multicase(ea=internal.types.integer, length=internal.types.integer)
    @classmethod
    def array(cls, ea, type, length):
        '''Set the data at the address `ea` to an array with the given `length` and `type`.'''

        if length <= 0:
            raise E.InvalidParameterError(u"{:s}.array({!s}, {!r}, {:d}) : Refusing to create an array of length {:d} at the specified address ({:#x}).".format('.'.join([__name__, cls.__name__]), ea, type, length, length, ea))

        # if the type is already specifying a list, then combine it with
        # the specified length
        if isinstance(type, internal.types.list):
            t, l = type
            realtype, reallength = [t, l * length], l * length

        # otherwise, promote it into an array
        else:
            realtype, reallength = [type, length], length

        # now we can figure out its IDA type and create the data. after
        # that, though, we need to update its refinfo before we leave.
        flags, typeid, nbytes = interface.typemap.resolve(realtype)
        if not idaapi.create_data(ea, flags, nbytes, typeid):
            raise E.DisassemblerError(u"{:s}.array({:#x}, {!r}, {:d}) : Unable to define the specified address ({:#x}) as an array of the requested length ({:d}).".format('.'.join([__name__, cls.__name__]), ea, type, length, ea, length))
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

        > res = database.get(ea)
        > res = database.get.signed()
        > res = database.get.unsigned(ea, 8, byteorder='big')
        > res = database.get.array(ea)
        > res = database.get.array(length=42)
        > res = database.get.structure(ea)
        > res = database.get.structure(ea, structure=structure.by('mystructure'))

    """
    @utils.multicase()
    def __new__(cls):
        '''Return the value for the item at the current address.'''
        return cls(ui.current.address())
    @utils.multicase(ea=internal.types.integer)
    def __new__(cls, ea):
        '''Return the value for the item at the address `ea`.'''
        return cls(ea, interface.address.size(ea))
    @utils.multicase(bounds=interface.bounds_t)
    def __new__(cls, bounds):
        '''Return the value for the item contained within the specified `bounds`.'''
        start, stop = sorted(bounds)
        return cls(start, stop - start, partial=True)
    @utils.multicase(ea=internal.types.integer, size=internal.types.integer)
    def __new__(cls, ea, size, **partial):
        """Return the value for the item at the address `ea` up to the given `size`.

        If `partial` is true, then decode as much of the item as possible leaving the result partially decoded.
        If `byteorder` is specified as `big` or `little` then force the decoding of the item to that byteorder.
        """
        FF_ALIGN, FF_STRLIT = map(idaapi.as_uint32, [idaapi.FF_ALIGN, idaapi.FF_STRLIT if hasattr(idaapi, 'FF_STRLIT') else idaapi.FF_ASCI])

        # Filter out the parameters we're able to hand off to any of the decoders we use.
        parameters = {kwarg : value for kwarg, value in partial.items() if kwarg in ['order', 'byteorder', 'partial']}

        # First get all the information about the address.
        flags, element = (F(interface.address.head(ea)) for F in [interface.address.flags, interface.address.element])
        info, dtype = idaapi.opinfo_t(), flags & interface.typemap.FF_MASKSIZE
        ok = idaapi.get_opinfo(interface.address.head(ea), idaapi.OPND_ALL, flags, info) if idaapi.__version__ < 7.0 else idaapi.get_opinfo(info, interface.address.head(ea), idaapi.OPND_ALL, flags)
        info = info if ok else None

        # If we're currently looking at code or alignment, then our job is easy
        # and we only need to return the bytes...as bytes.
        if flags & idaapi.MS_CLS == idaapi.FF_CODE or dtype in {FF_ALIGN}:
            return interface.address.read(ea, size)

        # Otherwise we're data and we first figure out if it's a structure, then
        # we just compare the sizes to distinguish it as an array or a single item.
        elif dtype in {idaapi.FF_STRUCT} and info and idaapi.get_struc(info.tid):
            sptr = internal.structure.new(info.tid, ea).ptr
            return cls.structure(ea, sptr, size, **parameters) if sptr.props & idaapi.SF_VAR or element >= size else interface.decode.array(flags, info, interface.address.read(ea, size), **parameters)

        # If this is a string, then we just need to unpack the strtype and use it.
        elif dtype in {FF_STRLIT}:
            width, length, _, encoding = interface.string.unpack(info.strtype)
            return cls.string(ea, width, length, encoding)

        # Anything else should be an integer, but we'll need to transform it
        # depending on the flags in order to get exactly what the user sees.
        bytes = interface.address.read(ea, size)
        maximum, integers = pow(2, 8 * element), interface.decode.array(flags & ~(idaapi.FF_SIGN|idaapi.FF_BNOT), info, bytes, **parameters)
        if flags & idaapi.FF_SIGN:
            result = [item - maximum if item else item for item in integers]
        elif flags & idaapi.FF_BNOT:
            result = [maximum + ~item if item else item for item in integers]
        else:
            result = [item for item in integers]

        # Figure out what our expected size should be, because if the result
        # doesn't fit what we expect and we're decoding the item partially,
        # then we'll need to include those extra bytes in the result we return.
        expected = element * len(result)
        if parameters.get('partial', False) and expected < len(bytes):
            return [item for item in itertools.chain(result, [bytes[expected:]])]
        return result if element < size else result[0]

    @utils.multicase()
    @classmethod
    def type(cls):
        '''Return the pythonic type for the current address.'''
        return cls.type(ui.current.address())
    @utils.multicase(ea=internal.types.integer)
    @classmethod
    def type(cls, ea):
        '''Return the pythonic type for the address `ea`.'''
        ea = interface.address.head(ea, warn=True)
        flags, info, size = interface.address.flags(ea), idaapi.opinfo_t(), interface.address.size(ea)
        ok = idaapi.get_opinfo(ea, idaapi.OPND_ALL, flags, info) if idaapi.__version__ < 7.0 else idaapi.get_opinfo(info, ea, idaapi.OPND_ALL, flags)
        return interface.typemap.dissolve(flags, info.tid if ok else idaapi.BADADDR, size, offset=ea)

    @utils.multicase()
    @classmethod
    def info(cls):
        '''Return the type information for the current address as an ``idaapi.tinfo_t``.'''
        return cls.info(ui.current.address())
    @utils.multicase(ea=internal.types.integer)
    @classmethod
    def info(cls, ea):
        '''Return the type information for the address `ea` as an ``idaapi.tinfo_t``.'''
        return interface.address.typeinfo(ea)
    typeinfo = utils.alias(info, 'get')

    @utils.multicase()
    @classmethod
    def unsigned(cls, **byteorder):
        '''Read an unsigned integer from the current address.'''
        ea = ui.current.address()
        return cls.unsigned(ea, interface.address.size(ea), **byteorder)
    @utils.multicase(ea=internal.types.integer)
    @classmethod
    def unsigned(cls, ea, **byteorder):
        '''Read an unsigned integer from the address `ea` using the size defined in the database.'''
        return cls.unsigned(ea, interface.address.size(ea), **byteorder)
    @utils.multicase(ea=internal.types.integer, size=internal.types.integer)
    @classmethod
    def unsigned(cls, ea, size, **byteorder):
        """Read an unsigned integer from the address `ea` with the specified `size`.

        If `byteorder` is 'big' then read in big-endian form.
        If `byteorder` is 'little' then read in little-endian form.

        The default value of `byteorder` is the same as specified by the database architecture.
        """
        data = interface.address.read(ea, size)
        order = builtins.next((byteorder[kwarg] for kwarg in ['order', 'byteorder'] if kwarg in byteorder), information.byteorder())
        if not isinstance(order, internal.types.string) or order.lower() not in {'big', 'little'}:
            raise internal.exceptions.InvalidParameterError(u"{:s}.unsigned({:#x}, {:d}{:s}) : An invalid byteorder ({:s}) that is not \"{:s}\" or \"{:s}\" was specified.".format('.'.join([__name__, cls.__name__]), ea, size, ", {:s}".format(internal.utils.string.kwargs(byteorder)) if byteorder else '', "\"{:s}\"".format(order) if isinstance(order, internal.types.string) else "{!s}".format(order), 'big', 'little'))
        return interface.decode.unsigned(data if order.lower() == 'big' else data[::-1])

    @utils.multicase()
    @classmethod
    def signed(cls, **byteorder):
        '''Read a signed integer from the current address.'''
        ea = ui.current.address()
        return cls.signed(ea, interface.address.size(ea), **byteorder)
    @utils.multicase(ea=internal.types.integer)
    @classmethod
    def signed(cls, ea, **byteorder):
        '''Read a signed integer from the address `ea` using the size defined in the database.'''
        return cls.signed(ea, interface.address.size(ea), **byteorder)
    @utils.multicase(ea=internal.types.integer, size=internal.types.integer)
    @classmethod
    def signed(cls, ea, size, **byteorder):
        """Read a signed integer from the address `ea` with the specified `size`.

        If `byteorder` is 'big' then read in big-endian form.
        If `byteorder` is 'little' then read in little-endian form.

        The default value of `byteorder` is the same as specified by the database architecture.
        """
        data = interface.address.read(ea, size)
        order = builtins.next((byteorder[kwarg] for kwarg in ['order', 'byteorder'] if kwarg in byteorder), information.byteorder())
        if not isinstance(order, internal.types.string) or order.lower() not in {'big', 'little'}:
            raise internal.exceptions.InvalidParameterError(u"{:s}.signed({:#x}, {:d}{:s}) : An invalid byteorder ({:s}) that is not \"{:s}\" or \"{:s}\" was specified.".format('.'.join([__name__, cls.__name__]), ea, size, ", {:s}".format(internal.utils.string.kwargs(byteorder)) if byteorder else '', "\"{:s}\"".format(order) if isinstance(order, internal.types.string) else "{!s}".format(order), 'big', 'little'))
        return interface.decode.signed(data if order.lower() == 'big' else data[::-1])

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
            return get.signed(**byteorder) if interface.address.flags(ui.current.address(), idaapi.FF_SIGN) else get.unsigned(**byteorder)
        @utils.multicase(ea=internal.types.integer)
        def __new__(cls, ea, **byteorder):
            '''Read an integer from the address `ea`.'''
            return get.signed(ea, **byteorder) if interface.address.flags(ea, idaapi.FF_SIGN) else get.unsigned(ea, **byteorder)
        @utils.multicase(ea=internal.types.integer, size=internal.types.integer)
        def __new__(cls, ea, size, **byteorder):
            '''Read an integer of the specified `size` from the address `ea`.'''
            return get.signed(ea, size, **byteorder) if interface.address.flags(ea, idaapi.FF_SIGN) else get.unsigned(ea, size, **byteorder)

        @utils.multicase()
        @classmethod
        def uint8_t(cls, **byteorder):
            '''Read a uint8_t from the current address.'''
            return get.unsigned(ui.current.address(), 1, **byteorder)
        @utils.multicase(ea=internal.types.integer)
        @classmethod
        def uint8_t(cls, ea, **byteorder):
            '''Read a uint8_t from the address `ea`.'''
            return get.unsigned(ea, 1, **byteorder)
        @utils.multicase()
        @classmethod
        def sint8_t(cls, **byteorder):
            '''Read a sint8_t from the current address.'''
            return get.signed(ui.current.address(), 1, **byteorder)
        @utils.multicase(ea=internal.types.integer)
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
        @utils.multicase(ea=internal.types.integer)
        @classmethod
        def uint16_t(cls, ea, **byteorder):
            '''Read a uint16_t from the address `ea`.'''
            return get.unsigned(ea, 2, **byteorder)
        @utils.multicase()
        @classmethod
        def sint16_t(cls, **byteorder):
            '''Read a sint16_t from the current address.'''
            return get.signed(ui.current.address(), 2, **byteorder)
        @utils.multicase(ea=internal.types.integer)
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
        @utils.multicase(ea=internal.types.integer)
        @classmethod
        def uint32_t(cls, ea, **byteorder):
            '''Read a uint32_t from the address `ea`.'''
            return get.unsigned(ea, 4, **byteorder)
        @utils.multicase()
        @classmethod
        def sint32_t(cls, **byteorder):
            '''Read a sint32_t from the current address.'''
            return get.signed(ui.current.address(), 4, **byteorder)
        @utils.multicase(ea=internal.types.integer)
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
        @utils.multicase(ea=internal.types.integer)
        @classmethod
        def uint64_t(cls, ea, **byteorder):
            '''Read a uint64_t from the address `ea`.'''
            return get.unsigned(ea, 8, **byteorder)
        @utils.multicase()
        @classmethod
        def sint64_t(cls, **byteorder):
            '''Read a sint64_t from the current address.'''
            return get.signed(ui.current.address(), 8, **byteorder)
        @utils.multicase(ea=internal.types.integer)
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
        @utils.multicase(ea=internal.types.integer)
        @classmethod
        def uint128_t(cls, ea, **byteorder):
            '''Read a uint128_t from the address `ea`.'''
            return get.unsigned(ea, 16, **byteorder)
        @utils.multicase()
        @classmethod
        def sint128_t(cls, **byteorder):
            '''Read a sint128_t from the current address.'''
            return get.signed(ui.current.address(), 16)
        @utils.multicase(ea=internal.types.integer)
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
            '''Read a floating-point number from the current address using the item size from the database.'''
            return cls(ui.current.address(), **byteorder)
        @utils.multicase(ea=internal.types.integer)
        def __new__(cls, ea, **byteorder):
            '''Read a floating-point number from the address `ea` using the item size from the database.'''
            size = interface.address.size(ea)
            return cls(ea, size, **byteorder)
        @utils.multicase(ea=internal.types.integer, size=internal.types.integer)
        def __new__(cls, ea, size, **byteorder):
            """Read a floating-point number from the address `ea` using the given `size`.

            If `byteorder` is 'big' then read in big-endian form.
            If `byteorder` is 'little' then read in little-endian form.

            The default value of `byteorder` is the same as specified by the database architecture.
            """
            available = [bits // 8 for bits in sorted(interface.decode.binary_float_table)]

            # First we need to figure out which byteorder that we're going to decode with.
            order = builtins.next((byteorder[kwarg] for kwarg in ['order', 'byteorder'] if kwarg in byteorder), information.byteorder())
            if not isinstance(order, internal.types.string) or order.lower() not in {'big', 'little'}:
                raise internal.exceptions.InvalidParameterError(u"{:s}({:#x}, {:d}{:s}) : An invalid byteorder ({:s}) that is not \"{:s}\" or \"{:s}\" was specified.".format('.'.join([__name__, 'get', cls.__name__]), ea, size, ", {:s}".format(internal.utils.string.kwargs(byteorder)) if byteorder else '', "\"{:s}\"".format(order) if isinstance(order, internal.types.string) else "{!s}".format(order), 'big', 'little'))

            # Next we need to validate the size and adjust it to the next valid one if necessary.
            if size and 8 * size not in interface.decode.binary_float_table:
                promoted = builtins.next((item for item in available if size <= item), available[-1])
                logging.warning(u"{:s}({:#x}, {:d}{:s}) : Promoting size ({:+d}) for floating-point number at {:#x} up to the next available floating-point size ({:+d}).".format('.'.join([__name__, 'get', cls.__name__]), ea, size, ", {:s}".format(internal.utils.string.kwargs(byteorder)) if byteorder else '', size, ea, promoted))

            # Otherwise we can use the size as-is and use it to read the necessary bytes.
            else:
                promoted = size

            # Now we just need to read the data and flip its byteorder before using our api
            bytes = interface.address.read(ea, promoted)
            return interface.decode.float(bytes if order.lower() == 'big' else bytes[::-1])

        @utils.multicase()
        @classmethod
        def half(cls, **byteorder):
            '''Read a half from the current address.'''
            return cls.half(ui.current.address(), **byteorder)
        @utils.multicase(ea=internal.types.integer)
        @classmethod
        def half(cls, ea, **byteorder):
            '''Read a half from the address `ea`.'''
            return cls(ea, 2, **byteorder)

        @utils.multicase()
        @classmethod
        def single(cls, **byteorder):
            '''Read a single from the current address.'''
            return cls.single(ui.current.address(), **byteorder)
        @utils.multicase(ea=internal.types.integer)
        @classmethod
        def single(cls, ea, **byteorder):
            '''Read a single from the address `ea`.'''
            return cls(ea, 4, **byteorder)

        @utils.multicase()
        @classmethod
        def double(cls, **byteorder):
            '''Read a double from the current address.'''
            return cls.double(ui.current.address(), **byteorder)
        @utils.multicase(ea=internal.types.integer)
        @classmethod
        def double(cls, ea, **byteorder):
            '''Read a double from the address `ea`.'''
            return cls(ea, 8, **byteorder)
    f = float   # XXX: ns alias

    @utils.multicase()
    @classmethod
    def array(cls, **byteorder):
        '''Return the values of the array at the current selection or address.'''
        address, selection = ui.current.address(), ui.current.selection()
        if 'length' in byteorder or operator.eq(*(interface.address.head(ea) for ea in selection)):
            return cls.array(address, **byteorder)
        return cls.array(selection, **byteorder)
    @utils.multicase(ea=internal.types.integer)
    @classmethod
    def array(cls, ea, **byteorder):
        '''Decode the data at the address `ea` as an array.'''
        if 'length' in byteorder or 'type' in byteorder:
            return cls.array(ea, byteorder.pop('length') if 'length' in byteorder else byteorder.pop('type'), **byteorder)
        bounds = interface.bounds_t(ea, ea + interface.address.size(ea))
        return cls.array(bounds, **byteorder)
    @utils.multicase(bounds=interface.bounds_t)
    @classmethod
    def array(cls, bounds, **byteorder):
        '''Decode the data within the provided `bounds` as an array.'''

        # Turn the boundaries we were given into a starting place and its size.
        start, stop = sorted(bounds)
        ea, size = start, stop - start

        # This should be easy and we only need to retrieve the type from the
        # starting address, read it, and then decode. We don't care about the
        # result from get_opinfo because if it fails, the flags are the type.
        info, flags = idaapi.opinfo_t(), interface.address.flags(ea)
        ok = idaapi.get_opinfo(ea, idaapi.OPND_ALL, flags, info) if idaapi.__version__ < 7.0 else idaapi.get_opinfo(info, ea, idaapi.OPND_ALL, flags)
        return interface.decode.array(flags, info if ok else None, interface.address.read(ea, size), **byteorder)
    @utils.multicase(bounds=interface.bounds_t)
    @classmethod
    def array(cls, bounds, type, **byteorder):
        '''Return the values within the provided `bounds` as an array of the pythonic element `type`.'''
        start, stop = sorted(bounds)
        expected, element = stop - start, interface.typemap.size(type)

        # First we'll sanity-test the type we were given is not a list (array)
        # so that we can complain to the user that we were given two lengths.
        if isinstance(type, internal.types.list):
            _, length = type
            if length * element != expected:
                raise E.InvalidParameterError(u"{:s}.array({:s}, {!s}) : The given element type ({!s}) is an array of {:d} element{:s} with a size ({:+#x}) that is different from the specified boundaries ({:+#x}).".format('.'.join([__name__, cls.__name__]), interface.bounds_t(*bounds), type, type, length, '' if length == 1 else 's', lenth * element, expected))
            logging.warning(u"{:s}.array({:s}, {!s}) : The given element type ({!s}) is an array that will have its length ({:d}) discarded due to an address range being given ({:s}).".format('.'.join([__name__, cls.__name__]), interface.bounds_t(*bounds), type, type, length, interface.bounds_t(*bounds)))
            type, _ = type

        # Now we can use the type to figure out how we're going to decode the
        # array, read the bytes using the bounds, and then decode it.
        info = idaapi.opinfo_t()
        flags, info.tid, size = interface.typemap.resolve(type)
        return interface.decode.array(flags, info, interface.address.read(start, expected), **byteorder)
    @utils.multicase(ea=internal.types.integer)
    @classmethod
    def array(cls, ea, type, **byteorder):
        '''Decode the data at the address `ea` as an array of the pythonic element `type`.'''
        if isinstance(type, internal.types.list):
            type, length = type
            return cls.array(ea, type, length, **byteorder)

        # If we got a length, then call the correct case to handle it.
        elif 'length' in byteorder:
            return cls.array(ea, type, byteorder.pop('length'), **byteorder)

        # Now we need the size of the item at the address that was specified
        # by the user, but we'll also need the offset our address is into that
        # item in case the user is doing a partial read into it. So we take
        # the difference and adjust our size with it to get the real size.
        offset = ea - interface.address.head(ea)
        size =  interface.address.size(ea) - offset

        # Now we can use the type to figure out how we're going to decode the
        # array, read the bytes using the address and size, and then decode it.
        info = idaapi.opinfo_t()
        flags, info.tid, _ = interface.typemap.resolve(type)
        return interface.decode.array(flags, info, interface.address.read(ea, size), **byteorder)
    @utils.multicase(ea=internal.types.integer, length=internal.types.integer)
    @classmethod
    def array(cls, ea, length, **byteorder):
        '''Decode the data at the address `ea` as a `length`-element array.'''

        # First thing we'll need to do is to get the type from whatever is
        # at the given address. We can ignore the get_opinfo result because
        # if there's no operand information, then the flags contain everything.
        info, flags = idaapi.opinfo_t(), interface.address.flags(ea)
        ok = idaapi.get_opinfo(ea, idaapi.OPND_ALL, flags, info) if idaapi.__version__ < 7.0 else idaapi.get_opinfo(info, ea, idaapi.OPND_ALL, flags)
        info = info if ok else None

        # Next we need to figure out the size of the operand information so
        # that we can use it with the length to calculate the amount that
        # we'll need to read. Afterwards, that's all we need for decoding.
        element = interface.address.element(flags, info)
        return interface.decode.array(flags, info, interface.address.read(ea, element * max(0, length)), **byteorder)
    @utils.multicase(ea=internal.types.integer, length=internal.types.integer)
    @classmethod
    def array(cls, ea, type, length, **byteorder):
        '''Decode the data at the address `ea` as a `length`-element array of the pythonic element `type`.'''
        flags, tid, size = interface.typemap.resolve(type)

        # Now we just need to verify that the resolved size and the element
        # size are the same to ensure we weren't given an array of some sort.
        if interface.typemap.size(type) != size:
            raise E.InvalidParameterError(u"{:s}.array({:#x}, {!s}, {:+d}) : Expected the given type ({!s}) to have a size ({:+d}) that is the same as the calculated size ({:+d}).".format('.'.join([__name__, cls.__name__]), ea, type, length, type, size, interface.typemap.size(type)))

        # All we need to do since we've resolved the type is to use the length
        # to calculate the amount of data to read, and then decode the array.
        info = idaapi.opinfo_t()
        info.tid = tid
        return interface.decode.array(flags, info, interface.address.read(ea, size * max(0, length)), **byteorder)

    @utils.multicase()
    @classmethod
    def string(cls, **strtype):
        '''Return the data at the current selection or address as a string with the specified `strtype` and `encoding`.'''
        address, selection = ui.current.address(), ui.current.selection()
        if 'length' in strtype or operator.eq(*(interface.address.head(ea) for ea in selection)):
            return cls.string(address, **strtype)
        return cls.string(selection, **strtype)
    @utils.multicase(bounds=interface.bounds_t)
    @classmethod
    def string(cls, bounds, **strtype):
        '''Return the data within the provided `bounds` as a string with the specified `strtype` and `encoding`.'''
        ea, _ = sorted(bounds)
        bounds, distance = interface.bounds_t(*bounds), operator.sub(*reversed(sorted(bounds)))

        # For older versions of IDA, we get the strtype from the opinfo
        if idaapi.__version__ < 7.0:
            res = interface.address.head(ea, warn=True)
            info, flags = idaapi.opinfo_t(), interface.address.flags(res)
            ok = idaapi.get_opinfo(res, idaapi.OPND_ALL, flags, info) if idaapi.__version__ < 7.0 else idaapi.get_opinfo(info, ea, idaapi.OPND_ALL, flags)
            res = info.strtype if ok else idaapi.BADADDR

        # Fetch the string type at the given address using the newer API
        else:
            res = idaapi.get_str_type(interface.address.head(ea, warn=True))

        # Figure out our defaults using either what we found or what the database says.
        default = interface.string.default()
        strtypeinfo, is_string = (default, False) if res in {idaapi.BADADDR, 0xffffffff, -1} else (res, True)
        width, layout, terminals, encoding = interface.string.unpack(strtypeinfo)

        # We first need to figure out the string type to calculate what the string
        # length means within the context of the bounds we were given as a parameter.
        if any(item in strtype for item in ['strtype', 'type']):
            res = builtins.next(strtype[item] for item in ['strtype', 'type'] if item in strtype)
            width, layout = res if isinstance(res, internal.types.ordered) else (res, 0)

        # If we were given a character width, then we might as well snag it and use it.
        elif 'width' in strtype:
            width = strtype['width']

        # Similar to the other cases that we've implemented, swap the layout with the
        # terminals if the layout was specified as terminal bytes.
        layout, terminals = (0, terminals) if isinstance(layout, internal.types.bytes) else (layout, terminals)

        # Now we have the character width and the size of the length prefix. So we take
        # the distance between our bounds and subtract the layout length from it.
        if layout > distance:
            logging.warning(u"{:s}.string({:s}{:s}) : Attempting to apply a string with a prefix length ({:d}) that is larger than the given boundaries ({:s}).".format('.'.join([__name__, cls.__name__]), bounds, u", {!s}".format(utils.string.kwargs(strtype)) if strtype else '', layout, bounds))
        leftover = distance - layout if distance > layout else 0

        # That was it, so we can now use the leftover bytes to calculate our new
        # bounds, and hand it off with the character width and string encoding.
        bounds = interface.bounds_t(ea + layout, ea + layout + leftover)
        return cls.string(bounds, width, strtype.get('encoding', encoding))
    @utils.multicase(ea=internal.types.integer)
    @classmethod
    def string(cls, ea, **strtype):
        """Return the data at the address specified by `ea` as a string with the specified `strtype` and `encoding`.

        The integer or tuple `strtype` contains the character width and the length prefix (or desired terminator) for the bytes representing the string.
        """

        # For older versions of IDA, we get the strtype from the opinfo
        if idaapi.__version__ < 7.0:
            res = interface.address.head(ea, warn=True)
            info, flags = idaapi.opinfo_t(), interface.address.flags(res)
            ok = idaapi.get_opinfo(res, idaapi.OPND_ALL, flags, info) if idaapi.__version__ < 7.0 else idaapi.get_opinfo(info, ea, idaapi.OPND_ALL, flags)
            res = info.strtype if ok else idaapi.BADADDR

        # Fetch the string type at the given address using the newer API
        else:
            res = idaapi.get_str_type(interface.address.head(ea, warn=True))

        # Figure out our defaults using either what we found or what the database says.
        default = interface.string.default()
        strtypeinfo, is_string = (default, False) if res in {idaapi.BADADDR, 0xffffffff, -1} else (res, True)
        width, layout, terminals, encoding = interface.string.unpack(strtypeinfo)

        # If we were given any keywords, then use them to update our strtype so that we
        # can force decode the string as what the user requests. We ensure we remove them
        # out of the parameters in case we hand them off to the `get.array` function.
        if any(kwd in strtype for kwd in ['type', 'strtype']):
            res = builtins.next((strtype.pop(item) for item in ['strtype', 'type'] if item in strtype))
            width, layout = res if isinstance(res, internal.types.ordered) else (res, 0)

        # If the user specified a character width, then use it instead of the default.
        elif 'width' in strtype:
            width = strtype['width']

        # Now we just need to check if we were given terminal characters for that layout,
        # because then those characters should be assigned to terminals with the layout
        # size being set to the value 0 which allows them to be used.
        layout, terminals = (0, terminals) if isinstance(layout, internal.types.bytes) else (layout, terminals)

        # That should be it as we have enough information and should be able to decode it.
        if 'length' in strtype:
            bounds = interface.bounds_t(ea + layout, ea + layout + width * strtype['length'])
            return cls.string(bounds, width, strtype.get('encoding', encoding))

        # If we're supposed to trust the layout (length prefix) but it's already marked as
        # a string, then we ignore it and trust the string size from the database. If the
        # layout includes a terminator, then we need to subtract the width to crop it.
        if is_string:
            leftover = interface.address.size(ea) - (layout or width)
            bounds = interface.bounds_t(ea + layout, ea + layout + leftover)
            return cls.string(bounds, width, strtype.get('encoding', encoding))

        # Otherwise they explicitly want it as a string and we do it as we're told.
        return cls.string(ea, width, layout if layout > 0 else terminals, strtype.get('encoding', encoding))

    # The following definitions for "get.string" explicitly trust their parameters
    # and do not infer any of their strtype information from the database. The only
    # thing they do is attempt to calculate the string length and adjust the address
    # so that it points at the correct location of the string (past the length prefix).

    @utils.multicase(ea=internal.types.integer, width=internal.types.integer, length=internal.types.integer, encoding=(internal.types.integer, internal.types.string, internal.types.none))
    @classmethod
    def string(cls, ea, width, length, encoding):
        '''Return the data at the address `ea` as a string with the given character `width`, `length` prefix, and string `encoding`.'''

        # If we were given a length of 0, then use the default string type
        # to figure out what our terminal characters should be.
        if length == 0:
            default = interface.string.default()
            _, _, terminals, _ = interface.string.unpack(default)
            return cls.string(ea, width, terminals, encoding)

        # Now we can read the length prefix from our address and use it to
        # calculate the actual boundaries that are occupied by our string.
        bounds = interface.bounds_t(ea + length, ea + length + width * cls.unsigned(ea, length))
        return cls.string(bounds, width, encoding)
    @utils.multicase(ea=internal.types.integer, width=internal.types.integer, terminal=internal.types.bytes, encoding=(internal.types.integer, internal.types.string, internal.types.none))
    @classmethod
    def string(cls, ea, width, terminal, encoding):
        '''Return the data at the address `ea` as a string with the given character `width` and string `encoding` that is terminated by the bytes in `terminal`.'''
        default = interface.string.default()
        _, _, default, _ = interface.string.unpack(default)

        # Some tests that are used to terminate reading if our current address
        # ends up being out of bounds or is not pointing to an initialized value.
        _, bottom = segment.bounds(ea)
        Fwithin_bounds = utils.fcompose(functools.partial(operator.sub, bottom), functools.partial(functools.partial, operator.gt))
        Finitialized = utils.fcompose(utils.frpartial(interface.address.flags, idaapi.FF_IVL), operator.truth)

        # Use the terminal characters we were given or the default terminals from
        # the database in order to create a test that stops when they're encountered.
        sentinel = bytearray(itertools.islice(itertools.chain(terminal or b'', default * width), width))
        Fis_terminator = utils.fcompose(functools.partial(read, size=width), functools.partial(operator.eq, builtins.bytes(sentinel)))

        # Now we have everything we need to read bytes from the database until we
        # encounter our terminator characters. Start at the address we were given
        # and read "width" bytes until we've stopped or can't proceed.
        iterable = itertools.count(ea, width)
        takewhile = utils.fcompose(utils.fmap(Fwithin_bounds(width), Finitialized, utils.fnot(Fis_terminator)), all)
        right = width + functools.reduce(utils.fpack(operator.itemgetter(1)), itertools.takewhile(takewhile, iterable), ea)

        # That should give us our very last valid address. Since we're returning just
        # the string, we don't need to add the width to include the terminator.
        bounds = interface.bounds_t(ea, right)
        return cls.string(bounds, width, encoding)

    # The functions that follow are actually responsible for reading and
    # decoding the string using the data from the database. The string
    # length is calculated from their first parameter so that it's up to
    # the caller to figure out which boundary contains the wanted string.

    @utils.multicase(bounds=interface.bounds_t, width=internal.types.integer, encoding=internal.types.string)
    @classmethod
    def string(cls, bounds, width, encoding):
        '''Return the data at the specified `bounds` as a string with the given character `width` and string `encoding`.'''
        bounds = interface.bounds_t(*bounds)

        # If the codec doesn't exist, then try and add it to the database.
        if interface.string.codec(width, encoding) is None:
            raise E.UnsupportedCapability(u"{:s}.string({:s}, {:d}, {!r}) : The requested string encoding ({:s}) is unavailable.".format('.'.join([__name__, cls.__name__]), bounds, width, encoding, utils.string.escape(encoding, '"')))

        # Grab its index and then recurse with the correct encoding index.
        index = interface.string.encoding(encoding)
        if index < 0:
            raise E.ItemNotFoundError(u"{:s}.string({:s}, {:d}, {!r}) : The requested string encoding ({:s}) could not be found in the database.".format('.'.join([__name__, cls.__name__]), bounds, width, encoding, utils.string.escape(encoding, '"')))
        return cls.string(bounds, width, index)
    @utils.multicase(bounds=interface.bounds_t, width=internal.types.integer, encoding=(internal.types.integer, internal.types.none))
    @classmethod
    def string(cls, bounds, width, encoding):
        '''Return the data at the specified `bounds` as a string with the given character `width` and string `encoding`.'''
        ea, _ = sorted(bounds)
        bounds, distance = interface.bounds_t(*bounds), operator.sub(*reversed(sorted(bounds)))

        # Now we know the width of the array we'll be reading, we need
        # to check that the boundaries directly fit inside of it.
        extra = distance % width
        if extra:
            logging.warning(u"{:s}.string({:s}, {:d}, {:d}) : Adjusting the given boundaries ({:s}) as the desired character width ({:d}) would result in {:+d} extra byte{:s}.".format('.'.join([__name__, cls.__name__]), bounds, width, encoding, bounds, width, extra, '' if extra == 1 else 's'))

        # Read the bytes that we need to decode and use the character
        # width to create an array that we'll use to decode our bytes.
        data = interface.address.read(ea, distance - extra)
        res = _array.array(utils.get_array_typecode(width, 1), data)

        # Next thing to do is to figure out which decoder to use, turn our
        # array into a string, and then decode it with the callable we got.
        codec = interface.string.codec(width, encoding)
        Fdecode = utils.fmap(utils.fidentity, len) if codec is None else functools.partial(codec.decode, errors='replace')
        data = res.tostring() if sys.version_info.major < 3 else res.tobytes()
        string, count = Fdecode(data)
        return string

    @utils.multicase()
    @classmethod
    def structure(cls, **byteorder):
        '''Return the decoded fields of the structure at current address as a dictionary.'''
        return cls.structure(ui.current.address(), **byteorder)
    @utils.multicase(ea=internal.types.integer)
    @classmethod
    def structure(cls, ea, **byteorder):
        '''Return the decoded fields of the structure at address `ea` as a dictionary.'''
        sid = type.structure.id(interface.address.head(ea))
        return cls.structure(ea, sid, **byteorder)
    @utils.multicase(ea=internal.types.integer, structure=(internal.structure.structure_t, idaapi.tinfo_t, internal.types.string, internal.types.integer))
    @classmethod
    def structure(cls, ea, structure, **byteorder):
        '''Return the decoded fields of the given `structure` from the address `ea` as a dictionary.'''
        st = _structure.by(structure)
        return cls.structure(ea, st.ptr, **byteorder)
    @utils.multicase(ea=internal.types.integer, sptr=idaapi.struc_t)
    @classmethod
    def structure(cls, ea, sptr, **byteorder):
        '''Return a dictionary containing the decoded fields of the structure represented by `sptr` using the data at address `ea`.'''
        if not _structure.has(sptr):
            raise E.StructureNotFoundError(u"{:s}.structure({:#x}, {:#x}{:s}) : Unable to find a structure with the specified identifier ({:#x}).".format(__name__, ea, sptr.id, u", {:s}".format(utils.string.kwargs(byteorder)) if byteorder else '', sptr.id))
        expected, size = _structure.size(sptr), interface.address.size(ea)
        return cls.structure(ea, sptr, size if sptr.props & idaapi.SF_VAR else expected, **byteorder)
    @utils.multicase(ea=internal.types.integer, structure=(idaapi.tinfo_t, internal.types.integer, internal.types.string), size=internal.types.integer)
    @classmethod
    def structure(cls, ea, structure, size, **byteorder):
        '''Return a dictionary containing the decoded fields of the given `structure` using `size` bytes from the data at address `ea`.'''
        if not _structure.has(structure):
            descr = "{:#x}".format(structure) if isinstance(structure, internal.types.integer) else "{!s}".format(structure) if isinstance(structure, idaapi.tinfo_t) else "\"{:s}\"".format(structure)
            raise E.StructureNotFoundError(u"{:s}.structure({:#x}, {:s}, {:+d}{:s}) : Unable to find the specified structure ({:s}).".format(__name__, ea, descr, size, u", {:s}".format(utils.string.kwargs(byteorder)) if byteorder else '', descr))

        # Extract the structure from what we were given and warn the user about any trickery we performed.
        st = _structure.by(structure)
        if isinstance(structure, idaapi.tinfo_t) and not any([structure.is_struct(), structure.is_union()]):
            typedescr = "{!s}".format(st.typeinfo)
            logging.warning(u"{:s}.structure({:#x}, {:s}, {:+d}{:s}) : The given type ({!s}) is not exactly a structure, but will result in its referenced structure ({!s}) being used.".format(__name__, ea, structure, size, u", {:s}".format(utils.string.kwargs(byteorder)) if byteorder else '', typedescr))

        # The user has been warned if necessary, so we can now hand things off to the real implementation.
        sptr = st.ptr
        return cls.structure(ea, sptr, size, **byteorder)
    @utils.multicase(ea=internal.types.integer, sptr=(idaapi.struc_t, internal.structure.structure_t), size=internal.types.integer)
    @classmethod
    def structure(cls, ea, sptr, size, **byteorder):
        '''Return a dictionary containing the decoded fields of the structure `sptr` using `size` bytes from the data at address `ea`.'''
        expected, sptr = idaapi.get_struc_size(sptr.id), sptr if isinstance(sptr, idaapi.struc_t) else sptr.ptr
        if size < expected:
            logging.warning(u"{:s}.structure({:#x}, {:#x}, {:+#x}) : The requested size ({:+d}) is smaller than the size of the structure ({:+d}) and will result in the result being partially initialized.".format('.'.join([__name__, cls.__name__]), ea, sptr.id, size, size, expected))

        elif size != expected and not sptr.props & idaapi.SF_VAR:
            logging.warning(u"{:s}.structure({:#x}, {:#x}, {:+#x}) : The requested size ({:+d}) is larger than the size of the structure ({:+d}) and will result in {:+d} byte{:s} being discarded.".format('.'.join([__name__, cls.__name__]), ea, sptr.id, size, size, expected, size - expected, '' if size - expected == 1 else 's'))

        # Now we can just read the data from the database and then decode our structure using it.
        bytes = interface.address.read(ea, size)
        fields = interface.decode.structure_bytes(sptr.id, bytes)
        return interface.decode.structure(sptr.id, fields, **byteorder)
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
            get_switch_info = idaapi.get_switch_info_ex if idaapi.__version__ < 7.0 else idaapi.get_switch_info

            # Technically a label for a switch is a code data type that is
            # referenced by by some data. We do this instead of checking the names.
            flags = interface.address.flags(ea)
            if flags & idaapi.MS_CLS == idaapi.FF_CODE and flags & idaapi.FF_REF:
                drefs = (address for address in interface.xref.data_address(ea, descend=False) if interface.address.flags(address, idaapi.MS_CLS) == idaapi.FF_DATA)

                # With the data references, we need need to walk up one more step
                # and grab any code references to it while looking for a switch.
                refs = (address for address in itertools.chain(*map(functools.partial(interface.xref.data_address, descend=False), drefs)) if interface.address.flags(address, idaapi.MS_CLS) == idaapi.FF_CODE and get_switch_info(address) is not None)

                # Now we'll just grab the very first reference we found. If we
                # got an address, then use it to grab the switch_info_t we want.
                address = builtins.next(refs, None)
                si = None if address is None else get_switch_info(address)

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

            # Grab all of the upward data references to the array at the given
            # address # that can give us an actual switch_info_t.
            refs = (address for address in interface.xref.data_address(ea, descend=False) if get_switch_info(address) is not None)

            # Then we can grab the first one and use it. If we didn't get a valid
            # reference, then we're not going to get a valid switch.
            address = builtins.next(refs, None)
            if address is None:
                si = None

            # We have an address, so now we can just straight-up snag the switch.
            else:
                si = get_switch_info(address)

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
            for address in interface.xref.code_address(ea, descend=True):
                found = not (get_switch_info(address) is None)

                if interface.node.identifier(address):
                    continue

                # If we actually grabbed the switch, then the current reference
                # actually is our only candidate and we should use it.
                if found:
                    candidates = (item for item in [address])

                # Otherwise if the reference is pointing to data, then treat
                # it an array where we need to follow the downward references.
                elif interface.address.flags(address, idaapi.MS_CLS) == idaapi.FF_DATA:
                    items = (case for case in interface.xref.code_address(address, descend=True))
                    candidates = (label for label in itertools.chain(*map(functools.partial(interface.xref.data_address, descend=False), items)) if get_switch_info(label))

                # Otherwise this must be code and so we'll check any of its
                # upward references to derive the necessary candidates.
                elif not found:
                    candidates = (label for label in xref.up(address) if get_switch_info(label))

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
            if not interface.function.has(ea):
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
        @utils.multicase(ea=internal.types.integer)
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
