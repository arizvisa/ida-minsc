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
that can be used for querying are `functions`, `segments`, `names`,
`imports`, `exports`, and `marks`.
"""

import six
from six.moves import builtins

import functools, operator, itertools, types
import sys, os, logging
import math, array, fnmatch, re, ctypes

import function, segment
import structure as _structure, instruction as _instruction
import ui, internal
from internal import utils, interface

import idaapi

## properties
def here():
    '''Return the current address.'''
    return ui.current.address()
h = utils.alias(here)

@utils.multicase()
def within():
    '''Should always return `True`.'''
    return within(ui.current.address())
@utils.multicase(ea=six.integer_types)
def within(ea):
    '''Returns `True` if address ``ea`` is within the bounds of the database.'''
    l, r = config.bounds()
    return l <= ea < r
contains = utils.alias(within)

def top():
    '''Return the very lowest address within the database.'''
    return config.bounds()[0]
def bottom():
    '''Return the very highest address within the database.'''
    return config.bounds()[1]

class config(object):
    """
    Namespace containing the various read-only properties about the database.
    This includes things such as the database boundaries, filenames, path to
    the generated database, etc. Some tools for determining the type of the
    binary are also included.
    """

    info = idaapi.get_inf_structure()

    @classmethod
    def filename(cls):
        '''Returns the filename that the database was built from.'''
        return idaapi.get_root_filename()

    @classmethod
    def idb(cls):
        '''Return the full path to the database.'''
        res = idaapi.cvar.database_idb if idaapi.__version__ < 7.0 else idaapi.get_path(idaapi.PATH_TYPE_IDB)
        return res.replace(os.sep, '/')

    @classmethod
    def module(cls):
        '''Return the module name as per the windows loader.'''
        res = cls.filename()
        res = os.path.split(res)
        return os.path.splitext(res[1])[0]

    @classmethod
    def path(cls):
        '''Return the full path to the directory containing the database.'''
        res = cls.idb()
        path, _ = os.path.split(res)
        return path

    @classmethod
    def baseaddress(cls):
        '''Returns the baseaddress of the database.'''
        return idaapi.get_imagebase()

    @classmethod
    def readonly(cls):
        '''Returns whether the database is read-only or not.'''
        if idaapi.__version__ >= 7.0:
            return cls.info.readonly_idb()
        raise NotImplementedError("{:s}.readonly() : This function is only supported on versions of IDA 7.0 and newer.".format('.'.join((__name__, cls.__name__))))

    @classmethod
    def sharedobject(cls):
        '''Returns whether the database is a shared-object or not.'''
        if idaapi.__version__ >= 7.0:
            return cls.info.is_dll()
        raise NotImplementedError("{:s}.sharedobject() : This function is only supported on versions of IDA 7.0 and newer.".format('.'.join((__name__, cls.__name__))))
    is_sharedobject = sharedQ = sharedobject

    @classmethod
    def changes(cls):
        '''Returns the number of changes within the database.'''
        if idaapi.__version__ >= 7.0:
            return cls.info.database_change_count
        raise NotImplementedError("{:s}.changes() : This function is only supported on versions of IDA 7.0 and newer.".format('.'.join((__name__, cls.__name__))))

    @classmethod
    def processor(cls):
        '''Returns the name of the processor configured by the database.'''
        if idaapi.__version__ >= 7.0:
            return cls.info.get_procName()
        raise NotImplementedError("{:s}.processor() : This function is only supported on versions of IDA 7.0 and newer.".format('.'.join((__name__, cls.__name__))))

    @classmethod
    def compiler(cls):
        '''Returns the configured compiler for the database.'''
        return cls.info.cc
    @classmethod
    def version(cls):
        '''Returns the database version.'''
        return cls.info.version

    @classmethod
    def type(cls, typestr):
        '''Evaluates a type string and returns its size according to the compiler used by the database.'''
        lookup = {
            'bool':'size_b',
            'short':'size_s',
            'int':'size_i', 'float':'size_l', 'single':'size_l',
            'long':'size_l',
            'longlong':'size_ll', 'double':'size_ll',
            'enum':'size_e',
            'longdouble':'size_ldbl',
            'align':'defalign', 'alignment':'defalign',
        }
        return getattr(cls.compiler(), lookup.get(typestr.translate(None, ' ').lower(), typestr) )

    @classmethod
    def bits(cls):
        '''Return number of bits of the processor used by the database.'''
        if cls.info.is_64bit():
            return 64
        elif cls.info.is_32bit():
            return 32
        raise ValueError("{:s}.bits() : Unknown bit size.".format('.'.join((__name__, cls.__name__))))

    @classmethod
    def byteorder(cls):
        '''Returns a string representing the byte-order used by integers in the database.'''
        if idaapi.__version__ < 7.0:
            res = idaapi.cvar.inf.mf
            return 'big' if res else 'little'
        return 'big' if cls.info.is_be() else 'little'

    @classmethod
    def processor(cls):
        '''Return processor name used by the database.'''
        return cls.info.procName

    @classmethod
    def main(cls):
        return cls.info.main

    @classmethod
    def entry(cls):
        if idaapi.__version__ < 7.0:
            return cls.info.beginEA
        return cls.info.start_ip

    @classmethod
    def margin(cls):
        return cls.info.margin

    @classmethod
    def bounds(cls):
        return cls.info.minEA, cls.info.maxEA

    class registers(object):
        """
        Namespace for returning the register names + sizes configured in the database.
        """
        @classmethod
        def names(cls):
            '''Return all of the register names in the database.'''
            return idaapi.ph_get_regnames()
        @classmethod
        def segments(cls):
            '''Return all of the segment registers in the database.'''
            names = cls.names()
            return [names[i] for i in six.moves.range(idaapi.ph_get_regFirstSreg(), idaapi.ph_get_regLastSreg()+1)]
        @classmethod
        def codesegment(cls):
            '''Return all of the code segment registers in the database.'''
            return cls.names()[idaapi.ph_get_regCodeSreg()]
        @classmethod
        def datasegment(cls):
            '''Return all of the data segment registers in the database.'''
            return cls.names()[idaapi.ph_get_regDataSreg()]
        @classmethod
        def segmentsize(cls):
            '''Return the segment register size for the database.'''
            return idaapi.ph_get_segreg_size()

range = bounds = utils.alias(config.bounds, 'config')
filename, idb, module, path = utils.alias(config.filename, 'config'), utils.alias(config.idb, 'config'), utils.alias(config.module, 'config'), utils.alias(config.path, 'config')
path = utils.alias(config.path, 'config')
baseaddress = base = utils.alias(config.baseaddress, 'config')

class functions(object):
    """
    Namespace used for listing all the functions inside the database. By
    default a list is returned containing the address of each function.

    The different types that one can match functions with are the following:
        `address` or `ea` - Match according to the function's address
        `name` - Match according to the exact name
        `like` - Filter the function names according to a glob
        `regex` - Filter the function names according to a regular-expression
        `predicate` - Filter the functions by passing their `idaapi.func_t` to a callable
    """
    __matcher__ = utils.matcher()
    __matcher__.boolean('name', operator.eq, utils.fcompose(function.by,function.name))
    __matcher__.boolean('like', lambda v, n: fnmatch.fnmatch(n, v), utils.fcompose(function.by,function.name))
    __matcher__.boolean('regex', re.search, utils.fcompose(function.by,function.name))
    __matcher__.predicate('predicate', function.by)
    __matcher__.predicate('pred', function.by)
    __matcher__.boolean('address', function.contains), __matcher__.boolean('ea', function.contains)

    # chunk matching
    #__matcher__.boolean('greater', operator.le, utils.fcompose(function.chunks, functools.partial(itertools.imap, operator.itemgetter(-1)), max)), __matcher__.boolean('gt', operator.lt, utils.fcompose(function.chunks, functools.partial(itertools.imap, operator.itemgetter(-1)), max))
    #__matcher__.boolean('less', operator.ge, utils.fcompose(function.chunks, functools.partial(itertools.imap, operator.itemgetter(0)), min)), __matcher__.boolean('lt', operator.gt, utils.fcompose(function.chunks, functools.partial(itertools.imap, operator.itemgetter(0)), min))

    # entry-point matching
    __matcher__.boolean('greater', operator.le, function.top), __matcher__.boolean('gt', operator.lt, function.top)
    __matcher__.boolean('less', operator.ge, function.top), __matcher__.boolean('lt', operator.gt, function.top)

    def __new__(cls):
        '''Returns a list of all of the functions in the current database (ripped from idautils).'''
        left, right = config.bounds()

        # find first function chunk
        ch = idaapi.get_fchunk(left) or idaapi.get_next_fchunk(left)
        while ch and ch.startEA < right and (ch.flags & idaapi.FUNC_TAIL) != 0:
            ch = idaapi.get_next_fchunk(ch.startEA)

        # iterate through the rest of the functions in the database
        result = []
        while ch and ch.startEA < right:
            result.append(ch.startEA)
            ch = idaapi.get_next_func(ch.startEA)
        return result

    @utils.multicase()
    @classmethod
    def __iterate__(cls):
        '''Iterates through all of the functions in the current database (ripped from idautils).'''
        left, right = config.bounds()

        # find first function chunk
        ch = idaapi.get_fchunk(left) or idaapi.get_next_fchunk(left)
        while ch and ch.startEA < right and (ch.flags & idaapi.FUNC_TAIL) != 0:
            ch = idaapi.get_next_fchunk(ch.startEA)

        # iterate through the rest of the functions in the database
        while ch and ch.startEA < right:
            yield ch.startEA
            ch = idaapi.get_next_func(ch.startEA)
        return

    @utils.multicase(string=basestring)
    @classmethod
    def iterate(cls, string):
        '''Iterate through all of the functions in the database with a glob that matches ``string``.'''
        return cls.iterate(like=string)
    @utils.multicase()
    @classmethod
    def iterate(cls, **type):
        '''Iterate through all of the functions in the database that match ``type``.'''
        if not type:
            #type = {'predicate':lambda n: True}
            for n in cls():
                yield n
            return
        res = cls()
        for key, value in six.iteritems(type):
            res = builtins.list(cls.__matcher__.match(key, value, res))
        for item in res: yield item

    @utils.multicase(string=basestring)
    @classmethod
    def list(cls, string):
        '''List all of the functions in the database with a glob that matches ``string``.'''
        return cls.list(like=string)
    @utils.multicase()
    @classmethod
    def list(cls, **type):
        """List all of the functions in the database that match ``type``.

        Search can be constrained by the named argument ``type``.
        like = glob match against function name
        ea, address = function contains address
        name = exact function name match
        regex = regular-expression against function name
        greater, less = greater-or-equal against bounds, less-or-equal against bounds
        pred = function predicate
        """
        res = builtins.list(cls.iterate(**type))

        flvars = lambda ea: _structure.fragment(function.frame(ea).id, 0, function.get_vars_size(ea)) if function.by(ea).frsize else []
        fminaddr = utils.fcompose(function.chunks, functools.partial(itertools.imap, operator.itemgetter(0)), min)
        fmaxaddr = utils.fcompose(function.chunks, functools.partial(itertools.imap, operator.itemgetter(-1)), max)

        maxindex = len(res)
        maxentry = max(res or [config.bounds()[0]])
        maxaddr = max(builtins.map(fmaxaddr, res) or [1])
        minaddr = max(builtins.map(fminaddr, res) or [1])
        maxname = max(builtins.map(utils.fcompose(function.name, len), res) or [1])
        chunks = max(builtins.map(utils.fcompose(function.chunks, builtins.list, len), res) or [1])
        marks = max(builtins.map(utils.fcompose(function.marks, builtins.list, len), res) or [1])
        blocks = max(builtins.map(utils.fcompose(function.blocks, builtins.list, len), res) or [1])
        exits = max(builtins.map(utils.fcompose(function.bottom, builtins.list, len), res) or [1])
        lvars = max(builtins.map(utils.fcompose(lambda ea: flvars(ea) if function.by(ea).frsize else [], builtins.list, len), res) or [1])

        # FIXME: fix function.arguments so that it works on non-stackbased functions
        fargs = function.arguments
        try:
            args = max(builtins.map(utils.fcompose(lambda ea: fargs(ea) if function.by(ea).frsize else [], builtins.list, len), res) or [1])
        except RuntimeError:
            args, fargs = 1, lambda ea: []

        cindex = math.ceil(math.log(maxindex or 1)/math.log(10)) if maxindex else 1
        cmaxoffset = math.floor(math.log(offset(maxentry)) or 1)/math.log(16)
        cmaxentry = math.floor(math.log(maxentry or 1)/math.log(16))
        cmaxaddr = math.floor(math.log(maxaddr or 1)/math.log(16))
        cminaddr = math.floor(math.log(minaddr or 1)/math.log(16))
        cchunks = math.floor(math.log(chunks or 1)/math.log(10)) if chunks else 1
        cmarks = math.floor(math.log(marks or 1)/math.log(10)) if marks else 1
        cblocks = math.floor(math.log(blocks or 1)/math.log(10)) if blocks else 1
        cargs = math.floor(math.log(args or 1)/math.log(10)) if args else 1
        cexits = math.floor(math.log(exits or 1)/math.log(10)) if exits else 1
        clvars = math.floor(math.log(lvars or 1)/math.log(10)) if lvars else 1

        for index, ea in enumerate(res):
            six.print_("[{:>{:d}d}] {:+#0{:d}x} : {:#0{:d}x}<>{:#0{:d}x} ({:<{:d}d}) : {:<{:d}s} : args:{:<{:d}d} lvars:{:<{:d}d} blocks:{:<{:d}d} exits:{:<{:d}d} marks:{:<{:d}d}".format(
                index, int(cindex),
                offset(ea), int(cmaxoffset),
                fminaddr(ea), int(cminaddr), fmaxaddr(ea), int(cmaxaddr),
                len(list(function.chunks(ea))), int(cchunks),
                function.name(ea), int(maxname),
                len(list(fargs(ea))) if function.by(ea).frsize else 0, int(cargs),
                len(list(flvars(ea))), int(clvars),
                len(list(function.blocks(ea))), int(cblocks),
                len(list(function.bottom(ea))), int(cexits),
                len(list(function.marks(ea))), int(cmarks)
            ))
        return

    @utils.multicase(string=basestring)
    @classmethod
    def search(cls, string):
        '''Search through all of the functions matching the glob ``string`` and return the first result.'''
        return cls.search(like=string)
    @utils.multicase()
    @classmethod
    def search(cls, **type):
        '''Search through all of the functions within the database and return the first result.'''
        query_s = ', '.join("{:s}={!r}".format(key, value) for key, value in six.iteritems(type))

        res = builtins.list(cls.iterate(**type))
        if len(res) > 1:
            builtins.map(logging.info, (("[{:d}] {:s}".format(i, function.name(ea))) for i, ea in enumerate(res)))
            f = utils.fcompose(function.by,function.name)
            logging.warn("{:s}.search({:s}) : Found {:d} matching results, returning the first one. : {!r}".format('.'.join((__name__, cls.__name__)), query_s, len(res), f(res[0])))

        res = builtins.next(iter(res), None)
        if res is None:
            raise LookupError("{:s}.search({:s}) : Found 0 matching results.".format('.'.join((__name__, cls.__name__)), query_s))
        return res

class segments(object):
    """
    Namespace used for listing all the segments inside the database. By
    default each segment's boundaries are yielded.

    The different types that one can match segments with are the following:
        `name` - Match according to the true segment name
        `like` - Filter the segment names according to a glob
        `regex` - Filter the segment names according to a regular-expression
        `index` - Match the segment by its index
        `identifier` - Match the segment by its identifier (`idaapi.segment_t.name`)
        `selector` - Match the segment by its selector (`idaapi.segment_t.sel`)
        `greater` or `gt` - Filter the segments for any after the specified address
        `less` or `lt` - Filter the segments for any before the specified address
        `predicate` - Filter the segments by passing its `idaapi.segment_t` to a callable
    """

    def __new__(cls):
        '''Yield the bounds of each segment within the current database.'''
        for s in segment.__iterate__():
            yield s.startEA, s.endEA
        return

    @utils.multicase(name=basestring)
    @classmethod
    def iterate(cls, name):
        '''List all of the segments defined in the database that match the glob ``name``.'''
        return cls.list(like=string)
    @utils.multicase()
    @classmethod
    def list(cls, **type):
        """List all the segments defined in the database.

        Search type can be identified by providing a named argument.
        like = glob match
        regex = regular expression
        selector = segment selector
        index = particular index
        name = specific segment name
        predicate = function predicate
        """
        return segment.list(**type)

    @utils.multicase(name=basestring)
    @classmethod
    def iterate(cls, name):
        '''Iterate through all of the segments in the database with a glob that matches ``name``.'''
        return cls.iterate(like=string)
    @utils.multicase()
    @classmethod
    def iterate(cls, **type):
        '''Iterate through each segment defined in the database.'''
        return segment.__iterate__(**type)

    @utils.multicase(name=basestring)
    @classmethod
    def search(cls, name):
        '''Search through all of the segments matching the glob ``name`` and return the first result.'''
        return cls.search(like=name)
    @utils.multicase()
    @classmethod
    def search(cls, **type):
        '''Search through all of the segments within the database and return the first result.'''
        return segment.search(**type)

@utils.multicase()
def instruction():
    '''Return the instruction at the current address as a string.'''
    return instruction(ui.current.address())
@utils.multicase(ea=six.integer_types)
def instruction(ea):
    '''Return the instruction at the address ``ea`` as a string.'''
    insn = idaapi.generate_disasm_line(interface.address.inside(ea))
    unformatted = idaapi.tag_remove(insn)
    comment = unformatted.rfind(idaapi.cvar.ash.cmnt)
    nocomment = unformatted[:comment] if comment != -1 else unformatted
    return reduce(lambda t, x: t + (('' if t.endswith(' ') else ' ') if x == ' ' else x), nocomment, '')

@utils.multicase()
def disassemble(**options):
    '''Disassemble the instructions at the current address.'''
    return disassemble(ui.current.address(), **options)
@utils.multicase(ea=six.integer_types)
def disassemble(ea, **options):
    """Disassemble the instructions at the address specified by ``ea``.

    If the integer ``count`` is specified, then return ``count`` number of instructions.
    If the bool ``comments`` is `True`, then return the comments for each instruction as well.
    """
    ea = interface.address.inside(ea)
    commentQ = builtins.next((options[k] for k in ('comment', 'comments') if k in options), False)

    res, count = [], options.get('count',1)
    while count > 0:
        insn = idaapi.generate_disasm_line(ea) or ''
        unformatted = idaapi.tag_remove(insn)
        comment = unformatted.rfind(idaapi.cvar.ash.cmnt)
        nocomment = unformatted[:comment] if comment != -1 and not commentQ else unformatted
        res.append("{:x}: {:s}".format(ea, reduce(lambda t, x: t + (('' if t.endswith(' ') else ' ') if x == ' ' else x), nocomment, '')) )
        ea = address.next(ea)
        count -= 1
    return '\n'.join(res)
disasm = utils.alias(disassemble)

def block(start, end):
    '''Return the block of bytes from address ``start`` to ``end``.'''
    if start > end:
        start, end = end, start
    start, end = interface.address.within(start, end)
    return read(start, end - start)
getBlock = getblock = get_block = read_block = utils.alias(block)

@utils.multicase()
def read():
    '''Return the bytes defined at the current address.'''
    res = ui.current.address()
    return read(res, type.size(res))
@utils.multicase(size=six.integer_types)
def read(size):
    '''Return ``size`` number of bytes from the current address.'''
    return read(ui.current.address(), size)
@utils.multicase(ea=six.integer_types, size=six.integer_types)
def read(ea, size):
    '''Return ``size`` number of bytes from address ``ea``.'''
    start, end = interface.address.within(ea, ea+size)
    return idaapi.get_many_bytes(ea, end-start) or ''

@utils.multicase(data=bytes)
def write(data, **original):
    '''Modify the database at the current address with the bytes ``data``.'''
    return write(ui.current.address(), data, **original)
@utils.multicase(ea=six.integer_types, data=bytes)
def write(ea, data, **original):
    """Modify the database at address ``ea`` with the bytes ``data``

    If the bool ``original`` is specified, then modify what IDA considers the original bytes.
    """
    ea, _ = interface.address.within(ea, ea + len(data))
    return idaapi.patch_many_bytes(ea, data) if original.get('original', False) else idaapi.put_many_bytes(ea, data)

class names(object):
    """
    Namespace used for listing all the names (or symbols) within the database.
    By default default the (address, name) is yielded.

    The different types that one can filter the symbols with are the following:
        `address` - Match according to the address of the symbol
        `name` - Match according to the name of the symbol
        `like` - Filter the symbol names according to a glob
        `regex` - Filter the symbol names according to a regular-expression
        `index` - Match the symbol according to its index
        `predicate` - Filter the symbols by passing their address to a callable
    """
    __matcher__ = utils.matcher()
    __matcher__.mapping('address', idaapi.get_nlist_ea), __matcher__.mapping('ea', idaapi.get_nlist_ea)
    __matcher__.boolean('name', operator.eq, idaapi.get_nlist_name)
    __matcher__.boolean('like', lambda v, n: fnmatch.fnmatch(n, v), idaapi.get_nlist_name)
    __matcher__.boolean('regex', re.search, idaapi.get_nlist_name)
    __matcher__.predicate('predicate', idaapi.get_nlist_ea)
    __matcher__.predicate('pred', idaapi.get_nlist_ea)
    __matcher__.attribute('index')

    def __new__(cls):
        for index in six.moves.range(idaapi.get_nlist_size()):
            res = zip((idaapi.get_nlist_ea, idaapi.get_nlist_name), (index,)*2)
            yield tuple(f(x) for f, x in res)
        return

    @utils.multicase(string=basestring)
    @classmethod
    def __iterate__(cls, string):
        return cls.__iterate__(like=string)
    @utils.multicase()
    @classmethod
    def __iterate__(cls, **type):
        if not type: type = {'predicate':lambda n: True}
        res = six.moves.range(idaapi.get_nlist_size())
        for key, value in six.iteritems(type):
            res = builtins.list(cls.__matcher__.match(key, value, res))
        for item in res: yield item

    @utils.multicase(string=basestring)
    @classmethod
    def iterate(cls, string):
        '''Iterate through all of the names in the database with a glob that matches ``string``.'''
        return cls.iterate(like=string)
    @utils.multicase()
    @classmethod
    def iterate(cls, **type):
        '''Iterate through all of the names in the database that match ``type``.'''
        for idx in cls.__iterate__(**type):
            yield idaapi.get_nlist_ea(idx), idaapi.get_nlist_name(idx)
        return

    @utils.multicase(string=basestring)
    @classmethod
    def list(cls, string):
        '''List all of the names in the database with a glob that matches ``string``.'''
        return cls.list(like=string)
    @utils.multicase()
    @classmethod
    def list(cls, **type):
        """List all of the names in the database that match ``type``.

        Search can be constrained by the named argument ``type``.
        like = glob match against name
        ea, address = name is at address
        name = exact name match
        regex = regular-expression against name
        index = name at index
        pred = function predicate
        """
        res = builtins.list(cls.__iterate__(**type))

        maxindex = max(res or [1])
        maxaddr = max(builtins.map(idaapi.get_nlist_ea, res) or [idaapi.BADADDR])
        cindex = math.ceil(math.log(maxindex or 1)/math.log(10))
        caddr = math.floor(math.log(maxaddr or 1)/math.log(16))

        for index in res:
            six.print_("[{:>{:d}d}] {:#0{:d}x} {:s}".format(index, int(cindex), idaapi.get_nlist_ea(index), int(caddr), idaapi.get_nlist_name(index)))
        return

    @utils.multicase(string=basestring)
    @classmethod
    def search(cls, string):
        '''Search through all of the names matching the glob ``string`` and return the first result.'''
        return cls.search(like=string)
    @utils.multicase()
    @classmethod
    def search(cls, **type):
        '''Search through all of the names within the database and return the first result.'''
        query_s = ', '.join("{:s}={!r}".format(key, value) for key, value in six.iteritems(type))

        res = builtins.list(cls.__iterate__(**type))
        if len(res) > 1:
            builtins.map(logging.info, (("[{:d}] {:x} {:s}".format(idx, idaapi.get_nlist_ea(idx), idaapi.get_nlist_name(idx))) for idx in res))
            f1, f2 = idaapi.get_nlist_ea, idaapi.get_nlist_name
            logging.warn("{:s}.search({:s}) : Found {:d} matching results, returning the first one. : {:x} {!r}".format('.'.join((__name__, cls.__name__)), query_s, len(res), f1(res[0]), f2(res[0])))

        res = builtins.next(iter(res), None)
        if res is None:
            raise LookupError("{:s}.search({:s}) : Found 0 matching results.".format('.'.join((__name__, cls.__name__)), query_s))
        return idaapi.get_nlist_ea(res)

    @classmethod
    def name(cls, ea):
        '''Return the symbol name of the string at address ``ea``.'''
        res = idaapi.get_nlist_idx(ea)
        return idaapi.get_nlist_name(res)
    @classmethod
    def address(cls, index):
        '''Return the address of the string at ``index``.'''
        return idaapi.get_nlist_ea(index)
    @classmethod
    def at(cls, ea):
        res = idaapi.get_nlist_idx(ea)
        return idaapi.get_nlist_ea(res), idaapi.get_nlist_name(res)

class search(object):
    """
    Namespace used for searching the database using IDA's find functionality.

    By default the name is used, however there are 3 search methods that are
    available. The methods that are provided are:

        `search.by_bytes` - Search by the specified hex bytes
        `search.by_regex` - Search by the specified regex
        `search.by_name`  - Search by the specified name

    Each search method has its own options, but all of them take an extra
    boolean option, `reverse`, which specifies whether to search backwards
    from the starting position or forwards.

    The `search.iterate` function allows one to iterate through all the results
    discovered in the database. One variation of `search.iterate` takes a 3rd
    parameter `predicate`. One can provide one of the search methods provided
    or include their own. This function will then yield each matched search
    result.
    """

    @utils.multicase(string=bytes)
    @staticmethod
    def by_bytes(string, **direction):
        '''Search through the database at the current address for the bytes specified by ``string``.'''
        return search.by_bytes(ui.current.address(), string, **direction)
    @utils.multicase(ea=six.integer_types, string=bytes, reverse=bool)
    @staticmethod
    def by_bytes(ea, string, **direction):
        """Search through the database at address ``ea`` for the bytes specified by ``string``.

        If ``reverse`` is specified as a bool, then search backwards from the given address.
        """
        flags = idaapi.SEARCH_UP if direction.get('reverse', False) else idaapi.SEARCH_DOWN
        return idaapi.find_binary(ea, idaapi.BADADDR, ' '.join("{:d}".format(six.byte2int(ch)) for ch in string), 10, idaapi.SEARCH_CASE | flags)
    byBytes = by_bytes

    @utils.multicase(string=basestring)
    @staticmethod
    def by_regex(string, **options):
        '''Search through the database at the current address for the regex matched by ``string``.'''
        return search.by_regex(ui.current.address(), string, **options)
    @utils.multicase(ea=six.integer_types, string=basestring)
    @staticmethod
    def by_regex(ea, string, **options):
        """Search the database at address ``ea`` for the regex matched by ``string``.

        If ``reverse`` is specified as a bool, then search backwards from the given address.
        If ``sensitive`` is specified as bool, then perform a case-sensitive search.
        """
        flags = idaapi.SEARCH_UP if options.get('reverse',False) else idaapi.SEARCH_DOWN
        flags |= idaapi.SEARCH_CASE if options.get('sensitive',False) else 0
        return idaapi.find_binary(ea, idaapi.BADADDR, string, options.get('radix',16), flags)
    byRegex = by_regex

    @utils.multicase(name=basestring)
    @staticmethod
    def by_name(name):
        '''Search through the database at the current address for the symbol ``name``.'''
        return idaapi.get_name_ea(idaapi.BADADDR, name)
    @utils.multicase(ea=six.integer_types, name=basestring)
    @staticmethod
    def by_name(ea, name):
        '''Search through the database at address ``ea`` for the symbol ``name``.'''
        return idaapi.get_name_ea(ea, name)
    byName = utils.alias(by_name, 'search')

    @utils.multicase(string=basestring)
    @staticmethod
    def iterate(string):
        '''Iterate through all results that match the bytes ``string`` starting at the current address.'''
        return search.iterate(ui.current.address(), string, search.by_bytes)
    @utils.multicase(start=six.integer_types, string=basestring)
    @staticmethod
    def iterate(start, string):
        '''Iterate through all results that match the bytes ``string`` starting at address ``start``.'''
        return search.iterate(start, string, search.by_bytes)
    @utils.multicase(start=six.integer_types, string=basestring)
    @staticmethod
    def iterate(start, string, predicate):
        '''Iterate through all searches matched by the function ``predicate`` and ``string`` starting at address ``start``.'''
        ea = predicate(start, string)
        while ea != idaapi.BADADDR:
            yield ea
            ea = predicate(ea+1, string)
        return

    def __new__(cls, string):
        '''Search through the database for the specified ``string``.'''
        return cls.by_name(here(), string)

byName = by_name = utils.alias(search.by_name, 'search')

def go(ea):
    '''Jump to the specified address at ``ea``.'''
    if isinstance(ea, basestring):
        ea = search.by_name(None, ea)
    idaapi.jumpto(interface.address.inside(ea))
    return ea

# returns the offset of ea from the baseaddress
@utils.multicase()
def offset():
    '''Return the current address converted to an offset from the base-address of the database.'''
    return offset(ui.current.address())
@utils.multicase(ea=six.integer_types)
def offset(ea):
    '''Return the address ``ea`` converted to an offset from the base-address of the database.'''
    return interface.address.inside(ea) - baseaddress()
getoffset = getOffset = o = utils.alias(offset)

def translate(offset):
    '''Translate the specified ``offset`` to an address in the database.'''
    return baseaddress()+offset
coof = convert_offset = convertOffset = utils.alias(translate)

def go_offset(offset):
    '''Jump to the specified ``offset`` within the database.'''
    res = ui.current.address()-baseaddress()
    ea = coof(offset)
    idaapi.jumpto(interface.address.inside(ea))
    return res
goof = gooffset = gotooffset = goto_offset = utils.alias(go_offset)

@utils.multicase()
def name(**flags):
    '''Returns the name at the current address.'''
    return name(ui.current.address(), **flags)
@utils.multicase(ea=six.integer_types)
def name(ea, **flags):
    """Return the name defined at the address specified by ``ea``.

    If ``flags`` is specified, then use the specified value as the flags.
    """
    ea = interface.address.inside(ea)

    # figure out what default flags to use
    fn = idaapi.get_func(ea)

    # figure out which name function to call
    if idaapi.__version__ < 6.8:
        # if get_true_name is going to return the function's name instead of a real one, then leave it as unnamed.
        if fn and fn.startEA == ea and not flags:
            return None

        aname = idaapi.get_true_name(ea) or idaapi.get_true_name(ea, ea)
    else:
        aname = idaapi.get_ea_name(ea, flags.get('flags', idaapi.GN_LOCAL))

    # return the name at the specified address or not
    return aname or None
@utils.multicase(string=basestring)
def name(string, *suffix, **flags):
    '''Renames the current address to ``string``.'''
    return name(ui.current.address(), string, *suffix, **flags)
@utils.multicase(none=types.NoneType)
def name(none, **flags):
    '''Removes the name at the current address.'''
    return name(ui.current.address(), '', **flags)
@utils.multicase(ea=six.integer_types, string=basestring)
def name(ea, string, *suffix, **flags):
    """Renames the address  specified by ``ea`` to ``string``.

    If ``ea`` is pointing to a global and is not contained by a function, then by default the label will be added to the Names list.
    If ``flags`` is specified, then use the specified value as the flags.
    If the boolean ``listed`` is specified, then specify whether to add the label to the Names list or not.
    """
    # combine name with its suffix
    res = (string,) + suffix
    string = interface.tuplename(*res)

    # validate the address
    ea = interface.address.inside(ea)

    # XXX: what's this for?
    if idaapi.has_any_name(type.flags(ea)):
        pass

    # XXX: isolate this default flags logic into a separate closure
    #      since this logic can be short-circuited by the 'flags' parameter.

    # some default options
    fl = idaapi.SN_NON_AUTO
    fl |= idaapi.SN_NOCHECK

    # preserve any flags that were previously applied
    fl |= 0 if idaapi.is_in_nlist(ea) else idaapi.SN_NOLIST
    fl |= idaapi.SN_WEAK if idaapi.is_weak_name(ea) else idaapi.SN_NON_WEAK
    fl |= idaapi.SN_PUBLIC if idaapi.is_public_name(ea) else idaapi.SN_NON_PUBLIC

    # set its local flag based on whether we're in a function or not
    fl = (fl | idaapi.SN_LOCAL) if function.within(ea) else (fl & ~idaapi.SN_LOCAL)

    # if we're within a function and 'listed' wasn't explicitly specified
    # then ensure it's not listed as it's likely to be a local label
    if not function.within(ea) and 'listed' not in flags:
        fl &= ~idaapi.SN_NOLIST

    # if the bool ``listed`` is True, then ensure that it's added to the name list.
    if 'listed' in flags:
        fl = (fl & ~idaapi.SN_NOLIST) if flags.get('listed', False) else (fl | idaapi.SN_NOLIST)

    # check to see if we're a label being applied to a switch
    # that way we can make it a local label
    try:
        # check if we're a label of some kind
        f = type.flags(ea)
        if idaapi.has_dummy_name(f) or idaapi.has_user_name(f):
            # that is referenced by an array with a correctly sized pointer inside it
            (r,sidata), = ((r,type.array(r)) for r in xref.data_up(ea))
            if config.bits() == sidata.itemsize*8 and ea in sidata:
                # which we check to see if its a switch_info_t
                si = next(idaapi.get_switch_info_ex(r) for r in xref.data_up(r))
                if si is not None:
                    # because its name has its local flag cleared
                    fl |= idaapi.SN_LOCAL
    except: pass

    # validate the name
    res = idaapi.validate_name2(buffer(string)[:]) if idaapi.__version__ < 7.0 else idaapi.validate_name(buffer(string)[:], idaapi.VNT_VISIBLE)
    if string and string != res:
        logging.warn("{:s}.name({:#x}, {!r}{:s}) : Stripping invalid chars from specified name. : {!r}".format(__name__, ea, string, ", {:s}".format(', '.join("{:s}={!r}".format(key, value) for key, value in six.iteritems(flags))) if flags else '', res))
        string = res

    # set the name and use the value of 'flags' if it was explicit
    res, ok = name(ea), idaapi.set_name(ea, string or "", flags.get('flags', fl))

    if not ok:
        raise ValueError("{:s}.name({:#x}, {!r}{:s}) : Unable to call idaapi.set_name({:#x}, {!r}, {:#x})".format(__name__, ea, string, ", {:s}".format(', '.join("{:s}={!r}".format(key, value) for key, value in six.iteritems(flags))) if flags else '', ea, string, flags.get('flags', fl)))
    return res
@utils.multicase(ea=six.integer_types, none=types.NoneType)
def name(ea, none, **flags):
    '''Removes the name defined at the address ``ea``.'''
    return name(ea, '', **flags)

def blocks(start, end):
    '''Returns each block between the addresses ``start`` and ``end``.'''
    block, _ = start, end = interface.address.head(start), address.tail(end)+1
    for ea in iterate(start, end):
        nextea = address.next(ea)

        if _instruction.is_call(ea):
            continue

        if _instruction.is_return(ea):
            yield block,nextea
            block = ea

        elif cxdown(ea):
            yield block,nextea
            block = nextea

        elif cxup(ea) and block != ea:
            yield block,ea
            block = ea
        continue
    return

# FIXME: The idaapi.is_basic_block_end api has got to be faster than doing it
#        with ida's xrefs in python..
if False:
    def blocks(start, end):
        '''Returns each block between the specified range of instructions.'''
        start, end = interface.address.head(start), address.tail(end)+1
        block = start
        for ea in iterate(start, end):
            nextea = address.next(ea)
            idaapi.decode_insn(ea)
            # XXX: for some reason idaapi.is_basic_block_end(...)
            #      occasionally includes some stray 'call' instructions.
            if idaapi.is_basic_block_end(ea):
                yield block,nextea
                block = nextea
            continue
        return

@utils.multicase()
def erase():
    '''Remove all of the defined tags at the current address.'''
    return erase(ui.current.address())
@utils.multicase(ea=six.integer_types)
def erase(ea):
    '''Remove all of the defined tags at address ``ea``.'''
    ea = interface.address.inside(ea)
    for k in tag(ea): tag(ea, k, None)
    color(ea, None)

@utils.multicase()
def color():
    '''Return the rgb color at the current address.'''
    return color(ui.current.address())
@utils.multicase(none=types.NoneType)
def color(none):
    '''Remove the color from the current address.'''
    return color(ui.current.address(), None)
@utils.multicase(ea=six.integer_types)
def color(ea):
    '''Return the rgb color at the address ``ea``.'''
    res = idaapi.get_item_color(interface.address.inside(ea))
    b,r = (res&0xff0000)>>16, res&0x0000ff
    return None if res == 0xffffffff else (r<<16)|(res&0x00ff00)|b
@utils.multicase(ea=six.integer_types, none=types.NoneType)
def color(ea, none):
    '''Remove the color at the address ``ea``.'''
    return idaapi.set_item_color(interface.address.inside(ea), 0xffffffff)
@utils.multicase(ea=six.integer_types, rgb=six.integer_types)
def color(ea, rgb):
    '''Set the color at address ``ea`` to ``rgb``.'''
    r,b = (rgb&0xff0000) >> 16, rgb&0x0000ff
    return idaapi.set_item_color(interface.address.inside(ea), (b<<16)|(rgb&0x00ff00)|r)

@utils.multicase()
def comment(**repeatable):
    '''Return the comment at the current address.'''
    return comment(ui.current.address(), **repeatable)
@utils.multicase(ea=six.integer_types)
def comment(ea, **repeatable):
    """Return the comment at the address ``ea``.

    If the bool ``repeatable`` is specified, then return the repeatable comment.
    """
    return idaapi.get_cmt(interface.address.inside(ea), repeatable.get('repeatable', False))
@utils.multicase(string=basestring)
def comment(string, **repeatable):
    '''Set the comment at the current address to ``string``.'''
    return comment(ui.current.address(), string, **repeatable)
@utils.multicase(ea=six.integer_types, string=basestring)
def comment(ea, string, **repeatable):
    """Set the comment at address ``ea`` to ``string``.

    If the bool ``repeatable`` is specified, then modify the repeatable comment.
    """
    res, ok = comment(ea, **repeatable), idaapi.set_cmt(interface.address.inside(ea), string, repeatable.get('repeatable', False))
    if not ok:
        raise ValueError("{:s}.comment({:#x}, {!r}{:s}) : Unable to call idaapi.set_cmt({:#x}, {!r}, {!s})".format(__name__, ea, string, ", {:s}".format(', '.join("{:s}={!r}".format(key, value) for key, value in six.iteritems(repeatable))) if repeatable else '', ea, string, repeatable.get('repeatable', False)))
    return res

class entries(object):
    """
    Namespace used for listing all of the entry points (or exports) within the
    database. By default the address of each entrypoint will be yielded.

    This namespace is also aliased as `database.exports`.

    The different types that one can match entrypoints with are the following:
        `address` or `ea` - Match according to the entrypoint's address
        `name` - Match according to the exact name
        `like` - Filter the entrypoint names according to a glob
        `regex` - Filter the entrypoint names according to a regular-expression
        `index` - Match according to the entrypoint's index (ordinal)
        `greater` or `gt` - Filter the entrypoints for any after the specified address
        `less` or `lt` - Filter the entrypoints for any before the specified address
        `predicate` - Filter the entrypoints by passing its index (ordinal) to a callable
    """

    __matcher__ = utils.matcher()
    __matcher__.mapping('address', utils.fcompose(idaapi.get_entry_ordinal, idaapi.get_entry))
    __matcher__.mapping('ea', utils.fcompose(idaapi.get_entry_ordinal, idaapi.get_entry))
    __matcher__.boolean('greater', operator.le, utils.fcompose(idaapi.get_entry_ordinal, idaapi.get_entry)), __matcher__.boolean('gt', operator.lt, utils.fcompose(idaapi.get_entry_ordinal, idaapi.get_entry))
    __matcher__.boolean('less', operator.ge, utils.fcompose(idaapi.get_entry_ordinal, idaapi.get_entry)), __matcher__.boolean('lt', operator.gt, utils.fcompose(idaapi.get_entry_ordinal, idaapi.get_entry))
    __matcher__.boolean('name', operator.eq, utils.fcompose(idaapi.get_entry_ordinal,idaapi.get_entry_name))
    __matcher__.boolean('like', lambda v, n: fnmatch.fnmatch(n, v), utils.fcompose(idaapi.get_entry_ordinal,idaapi.get_entry_name))
    __matcher__.boolean('regex', re.search, utils.fcompose(idaapi.get_entry_ordinal,idaapi.get_entry_name))
    __matcher__.predicate('predicate', idaapi.get_entry_ordinal)
    __matcher__.predicate('pred', idaapi.get_entry_ordinal)
    __matcher__.boolean('index', operator.eq)

    def __new__(cls):
        for ea in cls.iterate():
            yield ea
        return

    @utils.multicase(string=basestring)
    @classmethod
    def __iterate__(cls, string):
        return cls.__iterate__(like=string)
    @utils.multicase()
    @classmethod
    def __iterate__(cls, **type):
        if not type: type = {'predicate':lambda n: True}
        res = six.moves.range(idaapi.get_entry_qty())
        for key, value in six.iteritems(type):
            res = builtins.list(cls.__matcher__.match(key, value, res))
        for item in res: yield item

    @utils.multicase(string=basestring)
    @classmethod
    def iterate(cls, string):
        '''Iterate through all of the entry-points in the database with a glob that matches ``string``.'''
        return cls.iterate(like=string)
    @utils.multicase()
    @classmethod
    def iterate(cls, **type):
        '''Iterate through all of the entry-points in the database that match ``type``.'''
        res = itertools.imap(cls.__address__, cls.__iterate__(**type))
        for ea in res: yield ea

    @classmethod
    def __index__(cls, ea):
        '''Returns the index of the entry-point at the specified ``address``.'''
        f = utils.fcompose(idaapi.get_entry_ordinal, idaapi.get_entry)
        iterable = itertools.imap(utils.fcompose(utils.fmap(f, lambda n:n), builtins.tuple), six.moves.range(idaapi.get_entry_qty()))
        filterable = itertools.ifilter(utils.fcompose(utils.first, functools.partial(operator.eq, ea)), iterable)
        result = itertools.imap(utils.second, filterable)
        return builtins.next(result, None)

    @classmethod
    def __address__(cls, index):
        '''Returns the address of the entry-point at the specified ``index``.'''
        res = cls.__entryordinal__(index)
        res = idaapi.get_entry(res)
        return None if res == idaapi.BADADDR else res

    # Returns the name of the entry-point at the specified ``index``.
    __entryname__ = staticmethod(utils.fcompose(idaapi.get_entry_ordinal, idaapi.get_entry_name))
    # Returns the ordinal of the entry-point at the specified ``index``.
    __entryordinal__ = staticmethod(idaapi.get_entry_ordinal)

    @utils.multicase()
    @classmethod
    def ordinal(cls):
        '''Returns the ordinal of the entry-point at the current address.'''
        return cls.ordinal(ui.current.address())
    @utils.multicase(ea=six.integer_types)
    @classmethod
    def ordinal(cls, ea):
        '''Returns the ordinal of the entry-point at the address ``ea``.'''
        res = cls.__index__(ea)
        if res is not None:
            return cls.__entryordinal__(res)
        raise ValueError("{:s}.ordinal({:#x}) : No entry-point at specified address.".format('.'.join((__name__, cls.__name__)), ea))

    @utils.multicase()
    @classmethod
    def name(cls):
        '''Returns the name of the entry-point at the current address.'''
        return cls.name(ui.current.address())
    @utils.multicase(ea=six.integer_types)
    @classmethod
    def name(cls, ea):
        '''Returns the name of the entry-point at the address ``ea``.'''
        res = cls.__index__(ea)
        if res is not None:
            return cls.__entryname__(res)
        raise ValueError("{:s}.name({:#x}) : No entry-point at specified address.".format('.'.join((__name__, cls.__name__)), ea))

    @utils.multicase(string=basestring)
    @classmethod
    def list(cls, string):
        '''List all of the entry-points matching the glob ``string`` against the name.'''
        return cls.list(like=string)
    @utils.multicase()
    @classmethod
    def list(cls, **type):
        """List all of the entry-points within the database that match ``type`.

        Search can be constrained by the named argument ``type``.
        like = glob match against entry-point name
        ea, address = exact address match
        name = exact entry-point name match
        regex = regular-expression against entry-point name
        index = particular index
        greater, less = greater-or-equal against address, less-or-equal against address
        pred = function predicate
        """
        res = builtins.list(cls.__iterate__(**type))

        to_address = utils.fcompose(idaapi.get_entry_ordinal, idaapi.get_entry)
        to_numlen = utils.fcompose("{:x}".format, len)

        maxindex = max(res+[1])
        maxaddr = max(builtins.map(to_address, res) or [idaapi.BADADDR])
        maxordinal = max(builtins.map(idaapi.get_entry_ordinal, res) or [1])
        cindex = math.ceil(math.log(maxindex or 1)/math.log(10))
        caddr = math.floor(math.log(maxaddr or 1)/math.log(16))
        cordinal = math.floor(math.log(maxordinal or 1)/math.log(16))

        for index in res:
            six.print_("[{:{:d}d}] {:>#{:d}x} : ({:#{:d}x}) {:s}".format(index, int(cindex), to_address(index), int(caddr), cls.__entryordinal__(index), int(cindex), cls.__entryname__(index)))
        return

    @utils.multicase(string=basestring)
    @classmethod
    def search(cls, string):
        '''Search through all of the entry-point names matching the glob ``string`` and return the first result.'''
        return cls.search(like=string)
    @utils.multicase()
    @classmethod
    def search(cls, **type):
        '''Search through all of the entry-points within the database and return the first result.'''
        query_s = ', '.join("{:s}={!r}".format(key, value) for key, value in six.iteritems(type))

        res = builtins.list(cls.__iterate__(**type))
        if len(res) > 1:
            builtins.map(logging.info, (("[{:d}] {:x} : ({:x}) {:s}".format(idx, cls.__address__(idx), cls.__entryordinal__(idx), cls.__entryname__(idx))) for idx in res))
            f = utils.fcompose(idaapi.get_entry_ordinal, idaapi.get_entry)
            logging.warn("{:s}.search({:s}) : Found {:d} matching results, returning the first one. : {:x}".format('.'.join((__name__, cls.__name__)), query_s, len(res), f(res[0])))

        res = builtins.next(iter(res), None)
        if res is None:
            raise LookupError("{:s}.search({:s}) : Found 0 matching results.".format('.'.join((__name__, cls.__name__)), query_s))
        return cls.__address__(res)

    @utils.multicase()
    @classmethod
    def new(cls):
        '''Makes an entry-point at the current address.'''
        ea,entryname,ordinal = ui.current.address(), name(ui.current.address()) or function.name(ui.current.address()), idaapi.get_entry_qty()
        if entryname is None:
            raise ValueError("{:s}.new({:#x}) : Unable to determine name at address.".format( '.'.join((__name__, cls.__name__)), ea))
        return cls.new(ea, entryname, ordinal)
    @utils.multicase(ea=six.integer_types)
    @classmethod
    def new(cls, ea):
        '''Makes an entry-point at the specified address ``ea``.'''
        entryname, ordinal = name(ea) or function.name(ea), idaapi.get_entry_qty()
        if entryname is None:
            raise ValueError("{:s}.new({:#x}) : Unable to determine name at address.".format( '.'.join((__name__, cls.__name__)), ea))
        return cls.new(ea, entryname, ordinal)
    @utils.multicase(name=basestring)
    @classmethod
    def new(cls, name):
        '''Adds an entry-point to the database with the ``name`` using the next available index as the ordinal.'''
        return cls.new(ui.current.address(), name, idaapi.get_entry_qty())
    @utils.multicase(ea=six.integer_types, name=basestring)
    @classmethod
    def new(cls, ea, name):
        '''Makes the specified address ``ea`` an entry-point having the specified ``name``.'''
        ordinal = idaapi.get_entry_qty()
        return cls.new(ea, name, ordinal)
    @utils.multicase(name=basestring, ordinal=six.integer_types)
    @classmethod
    def new(cls, name, ordinal):
        '''Adds an entry-point with the specified ``name`` to the database using ``ordinal`` as its index.'''
        return cls.new(ui.current.address(), name, ordinal)
    @utils.multicase(ea=six.integer_types, name=basestring, ordinal=six.integer_types)
    @classmethod
    def new(cls, ea, name, ordinal):
        '''Adds an entry-point at ``ea`` with the specified ``name`` and ``ordinal``.'''
        res = idaapi.add_entry(ordinal, interface.address.inside(ea), name, 0)
        ui.state.wait()
        return res

    add = utils.alias(new, 'entry')
exports = entries     # XXX: ns alias

def tags():
    '''Returns all of the tag names used globally.'''
    return internal.comment.globals.name()

@utils.multicase()
def tag():
    '''Return all of the tags defined at the current address.'''
    return tag(ui.current.address())
@utils.multicase(ea=six.integer_types)
def tag(ea):
    '''Return all of the tags defined at address ``ea``.'''
    ea = interface.address.inside(ea)

    # if not within a function, then use a repeatable comment
    # otherwise, use a non-repeatable one
    try: func = function.by_address(ea)
    except: func = None
    repeatable = False if func else True

    # fetch the tags from the repeatable and non-repeatable comment at the given address
    res = comment(ea, repeatable=False)
    d1 = internal.comment.decode(res)
    res = comment(ea, repeatable=True)
    d2 = internal.comment.decode(res)

    # check to see if they're not overwriting each other
    if d1.viewkeys() & d2.viewkeys():
        logging.warn("{:s}.tag({:#x}) : Contents of both repeatable and non-repeatable comments conflict with one another. Giving the {:s} comment priority: {:s}".format(__name__, ea, 'repeatable' if repeatable else 'non-repeatable', ', '.join(d1.viewkeys() & d2.viewkeys())))

    # construct a dictionary that gives priority to repeatable if outside a function, and non-repeatable if inside
    res = {}
    builtins.map(res.update, (d1, d2) if repeatable else (d2, d1))

    # modify the decoded dictionary with any implicit tags
    aname = name(ea)
    if aname and type.flags(ea, idaapi.FF_NAME): res.setdefault('__name__', aname)
    eprefix = extra.get_prefix(ea)
    if eprefix is not None: res.setdefault('__extra_prefix__', eprefix)
    esuffix = extra.get_suffix(ea)
    if esuffix is not None: res.setdefault('__extra_suffix__', esuffix)
    col = color(ea)
    if col is not None: res.setdefault('__color__', col)

    # now return what the user cares about
    return res
@utils.multicase(key=basestring)
def tag(key):
    '''Return the tag identified by ``key`` at the current address.'''
    return tag(ui.current.address(), key)
@utils.multicase(key=basestring)
def tag(key, value):
    '''Set the tag identified by ``key`` to ``value`` at the current address.'''
    return tag(ui.current.address(), key, value)
@utils.multicase(ea=six.integer_types, key=basestring)
def tag(ea, key):
    '''Returns the tag identified by ``key`` from address ``ea``.'''
    res = tag(ea)
    return res[key]
@utils.multicase(ea=six.integer_types, key=basestring)
def tag(ea, key, value):
    '''Set the tag identified by ``key`` to ``value`` at the address ``ea``.'''
    if value is None:
        raise ValueError("{:s}.tag({:#x}, {!r}, ...) : Tried to set tag {!r} to an invalid value. : {!r}".format(__name__, ea, key, key, value))

    # if an implicit tag was specified, then dispatch to the correct handler
    if key == '__name__':
        return name(ea, value, listed=True)
    if key == '__extra_prefix__':
        return extra.set_prefix(ea, value)
    if key == '__extra_suffix__':
        return extra.set_suffix(ea, value)
    if key == '__color__':
        return color(ea, value)

    # if not within a function, then use a repeatable comment otherwise, use a non-repeatable one
    try: func = function.by_address(ea)
    except: func = None
    repeatable = False if func else True

    # grab the current tag out of the correct repeatable or non-repeatable comment
    ea = interface.address.inside(ea)
    state = internal.comment.decode(comment(ea, repeatable=not repeatable))
    state and comment(ea, '', repeatable=not repeatable) # clear the old one
    state.update(internal.comment.decode(comment(ea, repeatable=repeatable)))

    # update the tag's reference if we're actually adding a key and not overwriting it
    if key not in state:
        if func:
            internal.comment.contents.inc(ea, key)
        else:
            internal.comment.globals.inc(ea, key)

    # now we can actually update the tag and encode it into the comment
    res, state[key] = state.get(key, None), value
    comment(ea, internal.comment.encode(state), repeatable=repeatable)
    return res
@utils.multicase(key=basestring, none=types.NoneType)
def tag(key, none):
    '''Remove the tag identified by ``key`` from the current address.'''
    return tag(ui.current.address(), key, none)
@utils.multicase(ea=six.integer_types, key=basestring, none=types.NoneType)
def tag(ea, key, none):
    '''Removes the tag identified by ``key`` at the address ``ea``.'''
    ea = interface.address.inside(ea)

    # if the '__name__' is being cleared, then really remove it.
    if key == '__name__':
        return name(ea, None, listed=True)
    if key == '__extra_prefix__':
        return extra.del_prefix(ea)
    if key == '__extra_suffix__':
        return extra.del_suffix(ea)

    # if not within a function, then fetch the repeatable comment otherwise update the non-repeatable one
    try: func = function.by_address(ea)
    except: func = None
    repeatable = False if func else True

    # fetch the dict, remove the key, then write it back.
    state = internal.comment.decode(comment(ea, repeatable=not repeatable))
    state and comment(ea, '', repeatable=not repeatable) # clear the old one
    state.update(internal.comment.decode(comment(ea, repeatable=repeatable)))
    res = state.pop(key)
    comment(ea, internal.comment.encode(state), repeatable=repeatable)

    # delete its reference since it's been removed from the dict
    if func:
        internal.comment.contents.dec(ea, key)
    else:
        internal.comment.globals.dec(ea, key)

    # return the previous value back to the user because we're nice
    return res

# FIXME: consolidate the boolean querying logic into the utils module
# FIXME: document this properly
# FIXME: add support for searching global tags using the addressing cache
@utils.multicase(tag=basestring)
def select(tag, *And, **boolean):
    res = (tag,) + And
    boolean['And'] = tuple(builtins.set(boolean.get('And', builtins.set())).union(res))
    return select(**boolean)
@utils.multicase()
def select(**boolean):
    '''Fetch all of the functions containing the specified tags within its declaration'''
    containers = (builtins.tuple, builtins.set, builtins.list)
    boolean = {k : builtins.set(v if isinstance(v, containers) else (v,)) for k, v in boolean.viewitems()}

    # nothing specific was queried, so just yield all the tags
    if not boolean:
        for ea in internal.comment.globals.address():
            ui.navigation.set(ea)
            res = function.tag(ea) if function.within(ea) else tag(ea)
            if res: yield ea, res
        return

    # walk through all tags so we can cross-check them with the query
    for ea in internal.comment.globals.address():
        ui.navigation.set(ea)
        res, d = {}, function.tag(ea) if function.within(ea) else tag(ea)

        # Or(|) includes any tags that were queried
        Or = boolean.get('Or', builtins.set())
        res.update({key : value for key, value in six.iteritems(d) if key in Or})

        # And(&) includes any tags that match all of the queried tagnames
        And = boolean.get('And', builtins.set())
        if And:
            if And.intersection(d.viewkeys()) == And:
                res.update({key : value  for key, value in six.iteritems(d) if key in And})
            else: continue

        # if anything matched, then yield the address and the queried tags
        if res: yield ea, res
    return

# FIXME: consolidate the boolean querying logic into the utils module
# FIXME: document this properly
@utils.multicase(tag=basestring)
def selectcontents(tag, *Or, **boolean):
    res = (tag,) + Or
    boolean['Or'] = tuple(builtins.set(boolean.get('Or', builtins.set())).union(res))
    return selectcontents(**boolean)
@utils.multicase()
def selectcontents(**boolean):
    '''Fetch all of the functions containing the specified tags within its contents.'''
    containers = (builtins.tuple, builtins.set, builtins.list)
    boolean = {k : builtins.set(v if isinstance(v, containers) else (v,)) for k, v in boolean.viewitems()}

    # nothing specific was queried, so just yield all tagnames
    if not boolean:
        for ea, _ in internal.comment.contents.iterate():
            ui.navigation.procedure(ea)
            res = internal.comment.contents.name(ea)
            if res: yield ea, res
        return

    # walk through all tagnames so we can cross-check them against the query
    for ea, res in internal.comment.contents.iterate():
        ui.navigation.procedure(ea)
        res, d = builtins.set(res), internal.comment.contents._read(None, ea) or {}

        # check to see that the dict's keys match
        if builtins.set(d.viewkeys()) != res:
            # FIXME: include query in warning
            logging.warn("{:s}.selectcontents : Contents cache is out of sync. Using contents blob instead of supval. : {:#x}".format(__name__, ea))

        # now start aggregating the keys that the user is looking for
        res, d = builtins.set(), internal.comment.contents.name(ea)

        # Or(|) includes any of the tagnames being queried
        Or = boolean.get('Or', builtins.set())
        res.update(Or.intersection(d))

        # And(&) includes tags only if they include all of the specified tagnames
        And = boolean.get('And', builtins.set())
        if And:
            if And.intersection(d) == And:
                res.update(And)
            else: continue

        # if any tags matched, then yield the address and the results
        if res: yield ea, res
    return
selectcontent = utils.alias(selectcontents)

## imports
class imports(object):
    """
    Namespace used for listing all of the imports within the database. By
    default the (address, (shared-object, symbol-name, hint)) is yielded
    for each import.

    The different types that one can match imports with are the following:
        `address` or `ea` - Match according to the import's address
        `name` - Match according to the import's symbol name
        `module` - Filter the imports according to the specified module name
        `fullname` - Match according to the full symbol name (module + symbol)
        `like` - Filter the symbol names of all the imports according to a glob
        `regex` - Filter the symbol names of all the imports according to a regular-expression
        `ordinal` - Match according to the import's hint (ordinal)
        `index` - Match according index of the import
        `predicate` Filter the imports by passing the above (default) tuple to a callable
    """
    def __new__(cls):
        return cls.__iterate__()

    # FIXME: use "`" instead of "!" when analyzing an OSX fat binary

    __formats__ = staticmethod(lambda (module, name, ordinal): name or "Ordinal{:d}".format(ordinal))
    __formatl__ = staticmethod(lambda (module, name, ordinal): "{:s}!{:s}".format(module, imports.__formats__((module, name, ordinal))))
    __format__ = __formatl__

    __matcher__ = utils.matcher()
    __matcher__.mapping('address', utils.first), __matcher__.mapping('ea', utils.first)
    __matcher__.boolean('name', operator.eq, utils.fcompose(utils.second, __formats__.__func__))
    __matcher__.boolean('fullname', lambda v, n: fnmatch.fnmatch(n, v), utils.fcompose(utils.second, __formatl__.__func__))
    __matcher__.boolean('like', lambda v, n: fnmatch.fnmatch(n, v), utils.fcompose(utils.second, __formats__.__func__))
    __matcher__.boolean('module', lambda v, n: fnmatch.fnmatch(n, v), utils.fcompose(utils.second, utils.first))
    __matcher__.mapping('ordinal', utils.fcompose(utils.second, lambda(m,n,o): o))
    __matcher__.boolean('regex', re.search, utils.fcompose(utils.second, __format__))
    __matcher__.predicate('predicate', lambda n:n)
    __matcher__.predicate('pred', lambda n:n)
    __matcher__.mapping('index', utils.first)

    @classmethod
    def __iterate__(cls):
        """Iterate through all of the imports in the database.

        Yields `(address, (module, name, ordinal))` for each iteration.
        """
        for idx in six.moves.range(idaapi.get_import_module_qty()):
            module = idaapi.get_import_module_name(idx)
            result = []
            idaapi.enum_import_names(idx, utils.fcompose(utils.box, result.append, utils.fdiscard(lambda: True)))
            for ea, name, ordinal in result:
                yield ea, (module, name, ordinal)
            continue
        return

    @utils.multicase(string=basestring)
    @classmethod
    def iterate(cls, string):
        '''Iterate through all of the imports in the database with a glob that matches ``string``.'''
        return cls.iterate(like=string)
    @utils.multicase()
    @classmethod
    def iterate(cls, **type):
        '''Iterate through all of the imports in the database that match ``type``.'''
        if not type: type = {'predicate':lambda n: True}
        res = builtins.list(cls.__iterate__())
        for key, value in six.iteritems(type):
            res = builtins.list(cls.__matcher__.match(key, value, res))
        for item in res: yield item

    # searching
    @utils.multicase()
    @classmethod
    def at(cls):
        '''Returns the import at the current address.'''
        return cls.at(ui.current.address())
    @utils.multicase(ea=six.integer_types)
    @classmethod
    def at(cls, ea):
        '''Return the import at the address ``ea``.'''
        ea = interface.address.inside(ea)
        res = itertools.ifilter(utils.fcompose(utils.first, functools.partial(operator.eq, ea)), cls.__iterate__())
        try:
            return utils.second(builtins.next(res))
        except StopIteration:
            pass
        raise LookupError("{:s}.at({:#x}) : Unable to determine import at specified address.".format('.'.join((__name__, cls.__name__)), ea))

    @utils.multicase()
    @classmethod
    def module(cls):
        '''Return the import module at the current address.'''
        return cls.module(ui.current.address())
    @utils.multicase(ea=six.integer_types)
    @classmethod
    def module(cls, ea):
        '''Return the import module at the specified address ``ea``.'''
        ea = interface.address.inside(ea)
        for addr, (module, _, _) in cls.__iterate__():
            if addr == ea:
                return module
            continue
        raise LookupError("{:s}.module({:#x}) : Unable to determine import module name at specified address.".format('.'.join((__name__, cls.__name__)), ea))

    # specific parts of the import
    @utils.multicase()
    @classmethod
    def fullname(cls):
        '''Return the full name of the import at the current address.'''
        return cls.fullname(ui.current.address())
    @utils.multicase()
    @classmethod
    def fullname(cls, ea):
        '''Return the full name of the import at address ``ea``.'''
        return cls.__formatl__(cls.at(ea))

    @utils.multicase()
    @classmethod
    def name(cls):
        '''Return the name of the import at the current address.'''
        return cls.name(ui.current.address())
    @utils.multicase()
    @classmethod
    def name(cls, ea):
        '''Return the name of the import at address ``ea``.'''
        return cls.__formats__(cls.at(ea))

    @utils.multicase()
    @classmethod
    def ordinal(cls):
        '''Return the ordinal of the import at the current address.'''
        return cls.ordinal(ui.current.address())
    @utils.multicase()
    @classmethod
    def ordinal(cls, ea):
        '''Return the ordinal of the import at the address ``ea``.'''
        _, _, ordinal = cls.at(ea)
        return ordinal

    # FIXME: maybe implement a modules class for getting information on import modules
    @classmethod
    def modules(cls):
        '''Return all of the import modules defined in the database.'''
        return [idaapi.get_import_module_name(i) for i in six.moves.range(idaapi.get_import_module_qty())]

    @utils.multicase(string=basestring)
    @classmethod
    def list(cls, string):
        '''List all of the imports matching the glob ``string`` against the fullname.'''
        return cls.list(fullname=string)
    @utils.multicase()
    @classmethod
    def list(cls, **type):
        """List all of the imports in the database that match ``type``.

        Search can be constrained by the named argument ``type``.
        like = glob match against import short name
        ea, address = import is at address
        fullname = glob match against import long name -> MODULE!function
        module = glob match against module
        ordinal = exact match against import ordinal number
        name = exact match against import name
        regex = regular-expression against import name
        index = import name at index
        pred = function predicate
        """
        res = builtins.list(cls.iterate(**type))

        maxaddr = max(builtins.map(utils.first, res) or [idaapi.BADADDR])
        maxmodule = max(builtins.map(utils.fcompose(utils.second, utils.first, len), res) or [''])
        caddr = math.floor(math.log(maxaddr or 1)/math.log(16))
        cordinal = max(builtins.map(utils.fcompose(utils.second, operator.itemgetter(2), "{:d}".format, len), res) or [1])

        for ea, (module, name, ordinal) in res:
            six.print_("{:#0{:d}x} {:s}<{:<d}>{:s} {:s}".format(ea, int(caddr), module, ordinal, ' '*(cordinal-len("{:d}".format(ordinal)) + (maxmodule-len(module))), name))
        return

    @utils.multicase(string=basestring)
    @classmethod
    def search(cls, string):
        '''Search through all of the imports matching the fullname glob ``string``.'''
        return cls.search(fullname=string)
    @utils.multicase()
    @classmethod
    def search(cls, **type):
        '''Search through all of the imports within the database and return the first result.'''
        query_s = ', '.join("{:s}={!r}".format(key, value) for key, value in six.iteritems(type))

        res = builtins.list(cls.iterate(**type))
        if len(res) > 1:
            builtins.map(logging.info, ("{:x} {:s}<{:d}> {:s}".format(ea, module, ordinal, name) for ea, (module, name, ordinal) in res))
            f = utils.fcompose(utils.second, cls.__formatl__)
            logging.warn("{:s}.search({:s}) : Found {:d} matching results, returning the first one. : {!r}".format('.'.join((__name__, cls.__name__)), query_s, len(res), f(res[0])))

        res = builtins.next(iter(res), None)
        if res is None:
            raise LookupError("{:s}.search({:s}) : Found 0 matching results.".format('.'.join((__name__, cls.__name__)), query_s))
        return res[0]

getImportModules = utils.alias(imports.modules, 'imports')
getImports = utils.alias(imports.list, 'imports')

###
class address(object):
    """
    Namespace used for transforming an address in the database to another
    address according to various constraints. Essentially these functions are
    used to assist with navigation. These functions allow one to navigate
    between the next and previous "calls", data references, or even unknown
    (undefined) addresses.

    This namespace is also aliased as `database.a`.

    Some of the more common functions are used so often that they're also
    aliased as globals. Some of these are:
        `database.next` - Moving to the "next" address
        `database.prev` - Moving to the "previous" address
        `database.nextref` - Moving to the "next" address with a reference
        `database.prevref` - Moving to the "previous" address with a reference
        `database.nextreg` - Moving to the "next" address using a register
        `database.prevreg` - Moving to the "previous" address using a register
    """

    @staticmethod
    def __walk__(ea, next, match):
        '''Return the first address from ``ea`` using ``next`` for stepping until the provided callable doesn't ``match``.'''
        res = interface.address.inside(ea)
        while res not in {None, idaapi.BADADDR} and match(res):
            res = next(res)
        return res

    @utils.multicase(end=six.integer_types)
    @classmethod
    def iterate(cls, end):
        '''Iterate from the current address to ``end``.'''
        return cls.iterate(ui.current.address(), end)
    @utils.multicase(end=six.integer_types, step=callable)
    @classmethod
    def iterate(cls, end, step):
        '''Iterate from the current address to ``end`` using the callable ``step`` to determine the next address.'''
        return cls.iterate(ui.current.address(), end, step)
    @utils.multicase(start=six.integer_types, end=six.integer_types)
    @classmethod
    def iterate(cls, start, end):
        '''Iterate from address ``start`` to ``end``.'''
        start, end = builtins.map(interface.address.head, (start, end))
        step = cls.prev if start > end else cls.next
        return cls.iterate(start, end, step)
    @utils.multicase(start=six.integer_types, end=six.integer_types, step=callable)
    @classmethod
    def iterate(cls, start, end, step):
        '''Iterate from address ``start`` to ``end`` using the callable ``step`` to determine the next address.'''
        start, end = builtins.map(interface.address.head, (start, end))
        left, right = config.bounds()
        right = idaapi.prev_not_tail(right)

        if start == end: return
        op = operator.ge if start >= end else operator.lt

        res = start
        while res not in {idaapi.BADADDR, None} and left <= res < right and op(res, end):
            yield res
            res = step(res)
        return

    @utils.multicase()
    @classmethod
    def head(cls):
        '''Return the current address.'''
        return cls.head(ui.current.address())
    @utils.multicase(ea=six.integer_types)
    @classmethod
    def head(cls, ea):
        '''Return the address of the byte at the beginning of the address ``ea``.'''
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
        '''Return the address of the last byte at the end of the address at ``ea``.'''
        ea = interface.address.within(ea)
        return idaapi.get_item_end(ea)-1

    @utils.multicase()
    @classmethod
    def prev(cls):
        '''Return the previous address from the current address.'''
        return cls.prev(ui.current.address(), 1)
    @utils.multicase(predicate=builtins.callable)
    @classmethod
    def prev(cls, predicate):
        '''Return the previous address from the current address that matches ``predicate``.'''
        return cls.prev(ui.current.address(), predicate)
    @utils.multicase(ea=six.integer_types)
    @classmethod
    def prev(cls, ea):
        '''Return the previous address from the address specified by ``ea``.'''
        return cls.prev(ea, 1)
    @utils.multicase(ea=six.integer_types, predicate=builtins.callable)
    @classmethod
    def prev(cls, ea, predicate):
        '''Return the previous address from the address ``ea`` that matches ``predicate``.'''
        return cls.prevF(ea, predicate, 1)
    @utils.multicase(ea=six.integer_types, count=six.integer_types)
    @classmethod
    def prev(cls, ea, count):
        '''Return the `count`th previous address from the address specified by ``ea``.'''
        return cls.prevF(ea, utils.fidentity, count)
    @utils.multicase(ea=six.integer_types, predicate=builtins.callable, count=six.integer_types)
    @classmethod
    def prev(cls, ea, predicate, count):
        """Return the previous address from the address ``ea`` that matches ``predicate``.

        Skip ``count`` addresses before returning.
        """
        return cls.prevF(ea, predicate, count)

    @utils.multicase()
    @classmethod
    def next(cls):
        '''Return the next address from the current address.'''
        return cls.next(ui.current.address(), 1)
    @utils.multicase(predicate=builtins.callable)
    @classmethod
    def next(cls, predicate):
        '''Return the next address from the current address that matches ``predicate``.'''
        return cls.next(ui.current.address(), predicate)
    @utils.multicase(ea=six.integer_types)
    @classmethod
    def next(cls, ea):
        '''Return the next address from the address ``ea``.'''
        return cls.next(ea, 1)
    @utils.multicase(ea=six.integer_types, predicate=builtins.callable)
    @classmethod
    def next(cls, ea, predicate):
        '''Return the next address from the address ``ea`` that matches ``predicate``.'''
        return cls.nextF(ea, predicate, 1)
    @utils.multicase(ea=six.integer_types, count=six.integer_types)
    @classmethod
    def next(cls, ea, count):
        '''Return the `count`th next address from the address specified by ``ea``.'''
        return cls.nextF(ea, utils.fidentity, count)
    @utils.multicase(ea=six.integer_types, predicate=builtins.callable, count=six.integer_types)
    @classmethod
    def next(cls, ea, predicate, count):
        """Return the next address from the address ``ea`` that matches ``predicate``.

        Skip ``count`` addresses before returning.
        """
        return cls.nextF(ea, predicate, count)

    @utils.multicase(predicate=builtins.callable)
    @classmethod
    def prevF(cls, predicate):
        '''Return the previous address from the current one that matches ``predicate``.'''
        return cls.prevF(ui.current.address(), predicate, 1)
    @utils.multicase(ea=six.integer_types, predicate=builtins.callable)
    @classmethod
    def prevF(cls, ea, predicate):
        '''Return the previous address from the address ``ea``. that matches ``predicate``.'''
        return cls.prevF(ea, predicate, 1)
    @utils.multicase(ea=six.integer_types, predicate=builtins.callable, count=six.integer_types)
    @classmethod
    def prevF(cls, ea, predicate, count):
        """Return the previous address from the address ``ea`` that matches ``predicate``..

        Skip ``count`` addresses before returning.
        """
        Fprev, Finverse = utils.fcompose(interface.address.within, idaapi.prev_not_tail), utils.fcompose(predicate, operator.not_)

        # if we're at the very bottom address of the database
        # then skip the `interface.address.within` check.
        if ea == config.bounds()[1]:
            Fprev = idaapi.prev_not_tail

        if Fprev(ea) == idaapi.BADADDR:
            raise StandardError("{:s}.prevF: Refusing to seek past the top of the database: ({:#x} <= {:#x})".format('.'.join((__name__, cls.__name__)), ea, config.bounds()[0]))

        res = cls.__walk__(Fprev(ea), Fprev, Finverse)
        return cls.prevF(res, predicate, count-1) if count > 1 else res

    @utils.multicase(predicate=builtins.callable)
    @classmethod
    def nextF(cls, predicate):
        '''Return the next address from the current one that matches ``predicate``.'''
        return cls.nextF(ui.current.address(), predicate, 1)
    @utils.multicase(ea=six.integer_types, predicate=builtins.callable)
    @classmethod
    def nextF(cls, ea, predicate):
        '''Return the next address from the address ``ea``. that matches ``predicate``.'''
        return cls.nextF(ea, predicate, 1)
    @utils.multicase(ea=six.integer_types, predicate=builtins.callable, count=six.integer_types)
    @classmethod
    def nextF(cls, ea, predicate, count):
        """Return the next address from the address ``ea`` that matches ``predicate``..

        Skip ``count`` addresses before returning.
        """
        Fnext, Finverse = utils.fcompose(interface.address.within, idaapi.next_not_tail), utils.fcompose(predicate, operator.not_)
        if Fnext(ea) == idaapi.BADADDR:
            raise StandardError("{:s}.nextF: Refusing to seek past the bottom of the database: ({:#x} >= {:#x})".format('.'.join((__name__, cls.__name__)), idaapi.get_item_end(ea), config.bounds()[1]))
        res = cls.__walk__(Fnext(ea), Fnext, Finverse)
        return cls.nextF(res, predicate, count-1) if count > 1 else res

    @utils.multicase()
    @classmethod
    def prevref(cls):
        '''Returns the previous address that has anything referencing it.'''
        return cls.prevref(ui.current.address(), 1)
    @utils.multicase(predicate=builtins.callable)
    @classmethod
    def prevref(cls, predicate):
        '''Returns the previous address that has anything referencing it and matches ``predicate``.'''
        return cls.prevref(ui.current.address(), predicate)
    @utils.multicase(ea=six.integer_types)
    @classmethod
    def prevref(cls, ea):
        '''Returns the previous address from ``ea`` that has anything referencing it.'''
        return cls.prevref(ea, 1)
    @utils.multicase(ea=six.integer_types, predicate=builtins.callable)
    @classmethod
    def prevref(cls, ea, predicate):
        '''Returns the previous address from ``ea`` that has anything referencing it and matches ``predicate``.'''
        Fxref = utils.fcompose(xref.up, len, functools.partial(operator.lt, 0))
        F = utils.fcompose(utils.fmap(Fxref, predicate), builtins.all)
        return cls.prevF(ea, F, 1)
    @utils.multicase(ea=six.integer_types, count=six.integer_types)
    @classmethod
    def prevref(cls, ea, count):
        '''Returns the `count`th previous address from ``ea`` that has anything referencing it.'''
        Fxref = utils.fcompose(xref.up, len, functools.partial(operator.lt, 0))
        return cls.prevF(ea, Fxref, count)

    @utils.multicase()
    @classmethod
    def nextref(cls):
        '''Returns the next address that has anything referencing it.'''
        return cls.nextref(ui.current.address(), 1)
    @utils.multicase(predicate=builtins.callable)
    @classmethod
    def nextref(cls, predicate):
        '''Returns the next address that has anything referencing it and matches ``predicate``.'''
        return cls.nextref(ui.current.address(), predicate)
    @utils.multicase(ea=six.integer_types)
    @classmethod
    def nextref(cls, ea):
        '''Returns the next address from ``ea`` that has anything referencing it.'''
        return cls.nextref(ea, 1)
    @utils.multicase(ea=six.integer_types, predicate=builtins.callable)
    @classmethod
    def nextref(cls, ea, predicate):
        '''Returns the next address from ``ea`` that has anything referencing it and matches ``predicate``.'''
        Fxref = utils.fcompose(xref.up, len, functools.partial(operator.lt, 0))
        F = utils.fcompose(utils.fmap(Fxref, predicate), builtins.all)
        return cls.nextF(ea, Fxref, 1)
    @utils.multicase(ea=six.integer_types, count=six.integer_types)
    @classmethod
    def nextref(cls, ea, count):
        '''Returns the `count`th next address from ``ea`` that has anything referencing it.'''
        Fxref = utils.fcompose(xref.up, len, functools.partial(operator.lt, 0))
        return cls.nextF(ea, Fxref, count)

    @utils.multicase()
    @classmethod
    def prevdref(cls):
        '''Returns the previous address that has data referencing it.'''
        return cls.prevdref(ui.current.address(), 1)
    @utils.multicase(predicate=builtins.callable)
    @classmethod
    def prevdref(cls, predicate):
        '''Returns the previous address that has data referencing it and matches ``predicate``.'''
        return cls.prevdref(ui.current.address(), predicate)
    @utils.multicase(ea=six.integer_types)
    @classmethod
    def prevdref(cls, ea):
        '''Returns the previous address from ``ea`` that has data referencing it.'''
        return cls.prevdref(ea, 1)
    @utils.multicase(ea=six.integer_types, predicate=builtins.callable)
    @classmethod
    def prevdref(cls, ea, predicate):
        '''Returns the previous address from ``ea`` that has data referencing it and matches ``predicate``.'''
        Fdref = utils.fcompose(xref.data_up, len, functools.partial(operator.lt, 0))
        F = utils.fcompose(utils.fmap(Fdref, predicate), builtins.all)
        return cls.prevF(ea, F, 1)
    @utils.multicase(ea=six.integer_types, count=six.integer_types)
    @classmethod
    def prevdref(cls, ea, count):
        '''Returns the `count`th previous address from ``ea`` that has data referencing it.'''
        Fdref = utils.fcompose(xref.data_up, len, functools.partial(operator.lt, 0))
        return cls.prevF(ea, Fdref, count)

    @utils.multicase()
    @classmethod
    def nextdref(cls):
        '''Returns the next address that has data referencing it.'''
        return cls.nextdref(ui.current.address(), 1)
    @utils.multicase(predicate=builtins.callable)
    @classmethod
    def nextdref(cls, predicate):
        '''Returns the next address that has data referencing it and matches ``predicate``.'''
        return cls.nextdref(ui.current.address(), predicate)
    @utils.multicase(ea=six.integer_types)
    @classmethod
    def nextdref(cls, ea):
        '''Returns the next address from ``ea`` that has data referencing it.'''
        return cls.nextdref(ea, 1)
    @utils.multicase(ea=six.integer_types, predicate=builtins.callable)
    @classmethod
    def nextdref(cls, ea, predicate):
        '''Returns the next address from ``ea`` that has data referencing it and matches ``predicate``.'''
        Fdref = utils.fcompose(xref.data_up, len, functools.partial(operator.lt, 0))
        F = utils.fcompose(utils.fmap(Fdref, predicate), builtins.all)
        return cls.nextF(ea, F, 1)
    @utils.multicase(ea=six.integer_types, count=six.integer_types)
    @classmethod
    def nextdref(cls, ea, count):
        '''Returns the `count`th next address from ``ea`` that has data referencing it.'''
        Fdref = utils.fcompose(xref.data_up, len, functools.partial(operator.lt, 0))
        return cls.nextF(ea, Fdref, count)
    prevdata, nextdata = utils.alias(prevdref, 'address'), utils.alias(nextdref, 'address')

    @utils.multicase()
    @classmethod
    def prevcref(cls):
        '''Returns the previous address that has code referencing it.'''
        return cls.prevcref(ui.current.address(), 1)
    @utils.multicase(predicate=builtins.callable)
    @classmethod
    def prevcref(cls, predicate):
        '''Returns the previous address that has code referencing it and matches ``predicate``.'''
        return cls.prevcref(ui.current.address(), predicate)
    @utils.multicase(ea=six.integer_types)
    @classmethod
    def prevcref(cls, ea):
        '''Returns the previous address from ``ea`` that has code referencing it.'''
        return cls.prevcref(ea, 1)
    @utils.multicase(ea=six.integer_types, predicate=builtins.callable)
    @classmethod
    def prevcref(cls, ea, predicate):
        '''Returns the previous address from ``ea`` that has code referencing it and matches ``predicate``.'''
        Fcref = utils.fcompose(xref.code_up, len, functools.partial(operator.lt, 0))
        F = utils.fcompose(utils.fmap(Fcref, predicate), builtins.all)
        return cls.prevF(ea, Fcref, 1)
    @utils.multicase(ea=six.integer_types, count=six.integer_types)
    @classmethod
    def prevcref(cls, ea, count):
        '''Returns the `count`th previous address from ``ea`` that has code referencing it.'''
        Fcref = utils.fcompose(xref.code_up, len, functools.partial(operator.lt, 0))
        return cls.prevF(ea, Fcref, count)

    @utils.multicase()
    @classmethod
    def nextcref(cls):
        '''Returns the next address that has code referencing it.'''
        return cls.nextcref(ui.current.address(), 1)
    @utils.multicase(predicate=builtins.callable)
    @classmethod
    def nextcref(cls, predicate):
        '''Returns the next address that has code referencing it and matches ``predicate``.'''
        return cls.nextcref(ui.current.address(), predicate)
    @utils.multicase(ea=six.integer_types)
    @classmethod
    def nextcref(cls, ea):
        '''Returns the next address from ``ea`` that has code referencing it.'''
        return cls.nextcref(ea, 1)
    @utils.multicase(ea=six.integer_types, predicate=builtins.callable)
    @classmethod
    def nextcref(cls, ea, predicate):
        '''Returns the next address from ``ea`` that has code referencing it and matches ``predicate``.'''
        Fcref = utils.fcompose(xref.code_up, len, functools.partial(operator.lt, 0))
        F = utils.fcompose(utils.fmap(Fcref, predicate), builtins.all)
        return cls.nextF(ea, Fcref, 1)
    @utils.multicase(ea=six.integer_types, count=six.integer_types)
    @classmethod
    def nextcref(cls, ea, count):
        '''Returns the `count`th next address from ``ea`` that has code referencing it.'''
        Fcref = utils.fcompose(xref.code_up, len, functools.partial(operator.lt, 0))
        return cls.nextF(ea, Fcref, count)
    prevcode, nextcode = utils.alias(prevcref, 'address'), utils.alias(nextcref, 'address')

    @utils.multicase(reg=(basestring, interface.register_t))
    @classmethod
    def prevreg(cls, reg, *regs, **modifiers):
        '''Return the previous address containing an instruction that uses one of the specified registers ``regs``.'''
        return cls.prevreg(ui.current.address(), reg, *regs, **modifiers)
    @utils.multicase(predicate=builtins.callable, reg=(basestring, interface.register_t))
    @classmethod
    def prevreg(cls, predicate, reg, *regs, **modifiers):
        '''Return the previous address containing an instruction that uses one of the specified registers ``regs`` and matches ``predicate``.'''
        return cls.prevreg(ui.current.address(), predicate, reg, *regs, **modifiers)
    @utils.multicase(ea=six.integer_types, reg=(basestring, interface.register_t))
    @classmethod
    def prevreg(cls, ea, reg, *regs, **modifiers):
        '''Return the previous address from ``ea`` containing an instruction that uses one of the specified registers ``regs``.'''
        return cls.prevreg(ea, utils.fconst(True), reg, *regs, **modifiers)
    @utils.multicase(ea=six.integer_types, predicate=builtins.callable, reg=(basestring, interface.register_t))
    @classmethod
    def prevreg(cls, ea, predicate, reg, *regs, **modifiers):
        '''Return the previous address from ``ea`` containing an instruction that uses one of the specified registers ``regs`` and matches ``predicate``.'''
        regs = (reg,) + regs
        count = modifiers.get('count', 1)
        args = ', '.join(["{:x}".format(ea)] + builtins.map("\"{:s}\"".format, regs) + builtins.map(utils.unbox("{:s}={!r}".format), modifiers.items()))

        # generate each helper using the regmatch class
        iterops = interface.regmatch.modifier(**modifiers)
        uses_register = interface.regmatch.use(regs)

        # if within a function, then make sure we're within the chunk's bounds.
        if function.within(ea):
            (start, _) = function.chunk(ea)
            fwithin = functools.partial(operator.le, start)

        # otherwise ensure that we're not in the function and we're a code type.
        else:
            fwithin = utils.fcompose(utils.fmap(utils.fcompose(function.within, operator.not_), type.is_code), all)

            start = cls.__walk__(ea, cls.prev, fwithin)
            start = top() if start == idaapi.BADADDR else start

        # define a predicate for cls.walk to continue looping when true
        Freg = lambda ea: fwithin(ea) and not any(uses_register(ea, opnum) for opnum in iterops(ea))
        Fnot = utils.fcompose(predicate, operator.not_)
        F = utils.fcompose(utils.fmap(Freg, Fnot), builtins.any)

        ## skip the current address
        prevea = cls.prev(ea)
        if prevea is None:
            # FIXME: include registers in message
            logging.fatal("{:s}.prevreg({:s}, ...) : Unable to start walking from previous address. : {:#x}".format('.'.join((__name__, cls.__name__)), args, ea))
            return ea

        # now walk while none of our registers match
        res = cls.__walk__(prevea, cls.prev, F)
        if res in {None, idaapi.BADADDR} or (cls == address and res < start):
            # FIXME: include registers in message
            raise ValueError("{:s}.prevreg({:s}, ...) : Unable to find register{:s} within chunk. {:#x}{:+#x} : {:#x}".format('.'.join((__name__, cls.__name__)), args, '' if len(regs)==1 else 's', start, ea, res))

        # recurse if the user specified it
        modifiers['count'] = count - 1
        return cls.prevreg(res, predicate, *regs, **modifiers) if count > 1 else res

    @utils.multicase(reg=(basestring, interface.register_t))
    @classmethod
    def nextreg(cls, reg, *regs, **modifiers):
        '''Return the next address containing an instruction that uses one of the specified registers ``regs``.'''
        return cls.nextreg(ui.current.address(), reg, *regs, **modifiers)
    @utils.multicase(predicate=builtins.callable, reg=(basestring, interface.register_t))
    @classmethod
    def nextreg(cls, predicate, reg, *regs, **modifiers):
        '''Return the next address containing an instruction that uses one of the specified registers ``regs`` and matches ``predicate``.'''
        return cls.nextreg(ui.current.address(), predicate, reg, *regs, **modifiers)
    @utils.multicase(ea=six.integer_types, reg=(basestring, interface.register_t))
    @classmethod
    def nextreg(cls, ea, reg, *regs, **modifiers):
        '''Return the next address from ``ea`` containing an instruction that uses one of the specified registers ``regs``.'''
        return cls.nextreg(ea, utils.fconst(True), reg, *regs, **modifiers)
    @utils.multicase(ea=six.integer_types, predicate=builtins.callable, reg=(basestring, interface.register_t))
    @classmethod
    def nextreg(cls, ea, predicate, reg, *regs, **modifiers):
        '''Return the next address from ``ea`` containing an instruction that uses one of the specified registers ``regs`` and matches ``predicate``.'''
        regs = (reg,) + regs
        count = modifiers.get('count',1)
        args = ', '.join(["{:x}".format(ea)] + builtins.map("\"{:s}\"".format, regs) + builtins.map(utils.unbox("{:s}={!r}".format), modifiers.items()))

        # generate each helper using the regmatch class
        iterops = interface.regmatch.modifier(**modifiers)
        uses_register = interface.regmatch.use(regs)

        # if within a function, then make sure we're within the chunk's bounds.
        if function.within(ea):
            (_,end) = function.chunk(ea)
            fwithin = functools.partial(operator.gt, end)

        # otherwise ensure that we're not in a function and we're a code type.
        else:
            fwithin = utils.fcompose(utils.fmap(utils.fcompose(function.within, operator.not_), type.is_code), builtins.all)

            end = cls.__walk__(ea, cls.next, fwithin)
            end = bottom() if end == idaapi.BADADDR else end

        # define a predicate for cls.walk to continue looping when true
        Freg = lambda ea: fwithin(ea) and not any(uses_register(ea, opnum) for opnum in iterops(ea))
        Fnot = utils.fcompose(predicate, operator.not_)
        F = utils.fcompose(utils.fmap(Freg, Fnot), builtins.any)

        # skip the current address
        nextea = cls.next(ea)
        if nextea is None:
            # FIXME: include registers in message
            logging.fatal("{:s}.nextreg({:s}) : Unable to start walking from next address. : {:#x}".format('.'.join((__name__, cls.__name__)), args, ea))
            return ea

        # now walk while none of our registers match
        res = cls.__walk__(nextea, cls.next, F)
        if res in {None, idaapi.BADADDR} or (cls == address and res >= end):
            # FIXME: include registers in message
            raise ValueError("{:s}.nextreg({:s}, ...) : Unable to find register{:s} within chunk. {:#x}{:+#x} : {:#x}".format('.'.join((__name__, cls.__name__)), args, '' if len(regs)==1 else 's', ea, end, res))

        # recurse if the user specified it
        modifiers['count'] = count - 1
        return cls.nextreg(res, predicate, *regs, **modifiers) if count > 1 else res

    # FIXME: modify this to just locate _any_ amount of change in the sp delta by default
    @utils.multicase(delta=six.integer_types)
    @classmethod
    def prevstack(cls, delta):
        '''Return the previous instruction that is past the specified sp ``delta``.'''
        return cls.prevstack(ui.current.address(), delta)
    @utils.multicase(ea=six.integer_types, delta=six.integer_types)
    @classmethod
    def prevstack(cls, ea, delta):
        '''Return the previous instruction from ``ea`` that is past the specified sp ``delta``.'''
        logging.warn("{:s}.prevstack({:#x}, {:#x}) : This function's semantics are subject to change!".format('.'.join((__name__, cls.__name__)), ea, delta))
        fn, sp = function.top(ea), function.get_spdelta(ea)
        start, _ = function.chunk(ea)
        res = cls.__walk__(ea, cls.prev, lambda ea: ea >= start and abs(function.get_spdelta(ea) - sp) < delta)
        if res == idaapi.BADADDR or res < start:
            raise ValueError("{:s}.prevstack({:#x}, {:+#x}) : Unable to locate instruction matching contraints due to walking outside the bounds of the function {:#x} : {:#x} < {:#x} ".format('.'.join((__name__, cls.__name__)), ea, delta, fn, res, start))
        return res

    # FIXME: modify this to just locate _any_ amount of change in the sp delta by default
    @utils.multicase(delta=six.integer_types)
    @classmethod
    def nextstack(cls, delta):
        '''Return the next instruction that is past the sp delta ``delta``.'''
        return cls.nextstack(ui.current.address(), delta)
    @utils.multicase(ea=six.integer_types, delta=six.integer_types)
    @classmethod
    def nextstack(cls, ea, delta):
        '''Return the next instruction from ``ea`` that is past the sp delta ``delta``.'''
        logging.warn("{:s}.nextstack({:#x}, {:#x}) : This function's semantics are subject to change!".format('.'.join((__name__, cls.__name__)), ea, delta))
        fn, sp = function.top(ea), function.get_spdelta(ea)
        _, end = function.chunk(ea)
        res = cls.__walk__(ea, cls.next, lambda ea: ea < end and abs(function.get_spdelta(ea) - sp) < delta)
        if res == idaapi.BADADDR or res >= end:
            raise ValueError("{:s}.nextstack({:#x}, {:+#x}) : Unable to locate instruction matching contraints due to walking outside the bounds of the function {:#x} : {:#x} >= {:#x}".format('.'.join((__name__, cls.__name__)), ea, delta, fn, res, end))
        return res
    prevdelta, nextdelta = utils.alias(prevstack, 'address'), utils.alias(nextstack, 'address')

    @utils.multicase()
    @classmethod
    def prevcall(cls):
        '''Return the previous call instruction.'''
        return cls.prevcall(ui.current.address(), 1)
    @utils.multicase(predicate=builtins.callable)
    @classmethod
    def prevcall(cls, predicate):
        '''Return the previous call instruction that matches ``predicate``.'''
        return cls.prevcall(ui.current.address(), predicate)
    @utils.multicase(ea=six.integer_types)
    @classmethod
    def prevcall(cls, ea):
        '''Return the previous call instruction from the address ``ea``.'''
        return cls.prevcall(ea, 1)
    @utils.multicase(ea=six.integer_types, predicate=builtins.callable)
    @classmethod
    def prevcall(cls, ea, predicate):
        '''Return the previous call instruction from the address ``ea`` that matches ``predicate``.'''
        F = utils.fcompose(utils.fmap(_instruction.is_call, predicate), builtins.all)
        return cls.prevF(ea, F, 1)
    @utils.multicase(ea=six.integer_types, count=six.integer_types)
    @classmethod
    def prevcall(cls, ea, count):
        return cls.prevF(ea, _instruction.is_call, count)

    @utils.multicase()
    @classmethod
    def nextcall(cls):
        '''Return the next call instruction.'''
        return cls.nextcall(ui.current.address(), 1)
    @utils.multicase(predicate=builtins.callable)
    @classmethod
    def nextcall(cls, predicate):
        '''Return the next call instruction that matches ``predicate``.'''
        return cls.nextcall(ui.current.address(), predicate)
    @utils.multicase(ea=six.integer_types)
    @classmethod
    def nextcall(cls, ea):
        '''Return the next call instruction from the address ``ea``.'''
        return cls.nextcall(ea, 1)
    @utils.multicase(ea=six.integer_types, predicate=builtins.callable)
    @classmethod
    def nextcall(cls, ea, predicate):
        '''Return the next call instruction from the address ``ea`` that matches ``predicate``.'''
        F = utils.fcompose(utils.fmap(_instruction.is_call, predicate), builtins.all)
        return cls.nextF(ea, F, 1)
    @utils.multicase(ea=six.integer_types, count=six.integer_types)
    @classmethod
    def nextcall(cls, ea, count):
        return cls.nextF(ea, _instruction.is_call, count)

    @utils.multicase()
    @classmethod
    def prevbranch(cls):
        '''Return the previous branch instruction.'''
        return cls.prevbranch(ui.current.address(), 1)
    @utils.multicase(predicate=builtins.callable)
    @classmethod
    def prevbranch(cls, predicate):
        '''Return the previous branch instruction that matches ``predicate``.'''
        return cls.prevbranch(ui.current.address(), predicate)
    @utils.multicase(ea=six.integer_types)
    @classmethod
    def prevbranch(cls, ea):
        '''Return the previous branch instruction from the address ``ea``.'''
        return cls.prevbranch(ea, 1)
    @utils.multicase(ea=six.integer_types, predicate=builtins.callable)
    @classmethod
    def prevbranch(cls, ea, predicate):
        '''Return the previous branch instruction from the address ``ea`` that matches ``predicate``.'''
        Fnocall = utils.fcompose(_instruction.is_call, operator.not_)
        Fbranch = _instruction.is_branch
        Fx = utils.fcompose(utils.fmap(Fnocall, Fbranch), builtins.all)
        F = utils.fcompose(utils.fmap(Fx, predicate), builtins.all)
        return cls.prevF(ea, F, 1)
    @utils.multicase(ea=six.integer_types, count=six.integer_types)
    @classmethod
    def prevbranch(cls, ea, count):
        Fnocall = utils.fcompose(_instruction.is_call, operator.not_)
        Fbranch = _instruction.is_branch
        F = utils.fcompose(utils.fmap(Fnocall, Fbranch), builtins.all)
        return cls.prevF(ea, F, count)

    @utils.multicase()
    @classmethod
    def nextbranch(cls):
        '''Return the next branch instruction.'''
        return cls.nextbranch(ui.current.address(), 1)
    @utils.multicase(predicate=builtins.callable)
    @classmethod
    def nextbranch(cls, predicate):
        '''Return the next branch instruction that matches ``predicate``.'''
        return cls.nextbranch(ui.current.address(), predicate)
    @utils.multicase(ea=six.integer_types)
    def nextbranch(cls, ea):
        '''Return the next branch instruction from the address ``ea``.'''
        return cls.nextbranch(ea, 1)
    @utils.multicase(ea=six.integer_types, predicate=builtins.callable)
    def nextbranch(cls, ea, predicate):
        '''Return the next branch instruction from the address ``ea`` that matches ``predicate``.'''
        Fnocall = utils.fcompose(_instruction.is_call, operator.not_)
        Fbranch = _instruction.is_branch
        Fx = utils.fcompose(utils.fmap(Fnocall, Fbranch), builtins.all)
        F = utils.fcompose(utils.fmap(Fx, predicate), builtins.all)
        return cls.nextF(ea, F, 1)
    @utils.multicase(ea=six.integer_types, count=six.integer_types)
    @classmethod
    def nextbranch(cls, ea, count):
        Fnocall = utils.fcompose(_instruction.is_call, operator.not_)
        Fbranch = _instruction.is_branch
        F = utils.fcompose(utils.fmap(Fnocall, Fbranch), builtins.all)
        return cls.nextF(ea, F, count)

    @utils.multicase()
    @classmethod
    def prevlabel(cls):
        '''Return the address of the previous label.'''
        return cls.prevlabel(ui.current.address(), 1)
    @utils.multicase(predicate=builtins.callable)
    @classmethod
    def prevlabel(cls, predicate):
        '''Return the address of the previous label that matches ``predicate``.'''
        return cls.prevlabel(ui.current.address(), predicate)
    @utils.multicase(ea=six.integer_types)
    @classmethod
    def prevlabel(cls, ea):
        '''Return the address of the previous label from the address ``ea``.'''
        return cls.prevlabel(ea, 1)
    @utils.multicase(ea=six.integer_types, predicate=builtins.callable)
    @classmethod
    def prevlabel(cls, ea, predicate):
        '''Return the address of the previous label from the address ``ea`` that matches ``predicate``.'''
        Flabel = type.has_label
        F = utils.fcompose(utils.fmap(Flabel, predicate), builtins.all)
        return cls.prevF(ea, F, 1)
    @utils.multicase(ea=six.integer_types, count=six.integer_types)
    @classmethod
    def prevlabel(cls, ea, count):
        return cls.prevF(ea, type.has_label, count)

    @utils.multicase()
    @classmethod
    def nextlabel(cls):
        '''Return the address of the next label.'''
        return cls.nextlabel(ui.current.address(), 1)
    @utils.multicase(predicate=builtins.callable)
    @classmethod
    def nextlabel(cls, predicate):
        '''Return the address of the next label that matches ``predicate``.'''
        return cls.nextlabel(ui.current.address(), predicate)
    @utils.multicase(ea=six.integer_types)
    @classmethod
    def nextlabel(cls, ea):
        '''Return the address of the next label from the address ``ea``.'''
        return cls.nextlabel(ea, 1)
    @utils.multicase(ea=six.integer_types, predicate=builtins.callable)
    @classmethod
    def nextlabel(cls, ea, predicate):
        '''Return the address of the next label from the address ``ea`` that matches ``predicate``.'''
        Flabel = type.has_label
        F = utils.fcompose(utils.fmap(Flabel, predicate), builtins.all)
        return cls.nextF(ea, F, 1)
    @utils.multicase(ea=six.integer_types, count=six.integer_types)
    @classmethod
    def nextlabel(cls, ea, count):
        return cls.nextF(ea, type.has_label, count)

    @utils.multicase()
    @classmethod
    def prevtag(cls, **tagname):
        '''Return the previous address that contains a tag.'''
        return cls.prevtag(ui.current.address(), 1, **tagname)
    @utils.multicase(predicate=builtins.callable)
    @classmethod
    def prevtag(cls, predicate, **tagname):
        '''Return the previous address that contains a tag and matches ``predicate``.'''
        return cls.prevtag(ui.current.address(), predicate, **tagname)
    @utils.multicase(ea=six.integer_types)
    @classmethod
    def prevtag(cls, ea, **tagname):
        """Returns the previous address from ``ea`` that contains a tag.

        If the string ``tagname`` is specified, then only return the address if the specified tag is defined.
        """
        return cls.prevtag(ea, 1, **tagname)
    @utils.multicase(ea=six.integer_types, predicate=builtins.callable)
    @classmethod
    def prevtag(cls, ea, predicate, **tagname):
        '''Returns the previous address from ``ea`` that contains a tag and matches ``predicate.'''
        tagname = tagname.get('tagname', None)
        Ftag = type.has_comment if tagname is None else utils.fcompose(tag, utils.frpartial(operator.contains, tagname))
        F = utils.fcompose(utils.fmap(Ftag, predicate), builtins.all)
        return cls.prevF(ea, F, 1)
    @utils.multicase(ea=six.integer_types, count=six.integer_types)
    @classmethod
    def prevtag(cls, ea, count, **tagname):
        tagname = tagname.get('tagname', None)
        Ftag = type.has_comment if tagname is None else utils.fcompose(tag, utils.frpartial(operator.contains, tagname))
        return cls.prevF(ea, Ftag, count)

    @utils.multicase()
    @classmethod
    def nexttag(cls, **tagname):
        '''Return the next address that contains a tag.'''
        return cls.nexttag(ui.current.address(), 1, **tagname)
    @utils.multicase(predicate=builtins.callable)
    @classmethod
    def nexttag(cls, predicate, **tagname):
        '''Return the next address that contains a tag and matches ``predicate``.'''
        return cls.nexttag(ui.current.address(), predicate, **tagname)
    @utils.multicase(ea=six.integer_types)
    @classmethod
    def nexttag(cls, ea, **tagname):
        """Returns the next address from ``ea`` that contains a tag.

        If the string ``tagname`` is specified, then only return the address if the specified tag is defined.
        """
        return cls.nexttag(ea, 1, **tagname)
    @utils.multicase(ea=six.integer_types, predicate=builtins.callable)
    @classmethod
    def nexttag(cls, ea, predicate, **tagname):
        '''Returns the next address from ``ea`` that contains a tag and matches ``predicate``.'''
        tagname = tagname.get('tagname', None)
        Ftag = type.has_comment if tagname is None else utils.fcompose(tag, utils.frpartial(operator.contains, tagname))
        F = utils.fcompose(utils.fmap(Ftag, predicate), builtins.all)
        return cls.nextF(ea, F, 1)
    @utils.multicase(ea=six.integer_types, count=six.integer_types)
    @classmethod
    def nexttag(cls, ea, count, **tagname):
        tagname = tagname.get('tagname', None)
        Ftag = type.has_comment if tagname is None else utils.fcompose(tag, utils.frpartial(operator.contains, tagname))
        return cls.nextF(ea, Ftag, count)
    prevcomment, nextcomment = utils.alias(prevtag, 'address'), utils.alias(nexttag, 'address')

    @utils.multicase()
    @classmethod
    def prevunknown(cls):
        '''Return the previous address that is undefined.'''
        return cls.prevunknown(ui.current.address(), 1)
    @utils.multicase(predicate=builtins.callable)
    @classmethod
    def prevunknown(cls, predicate):
        '''Return the previous address that is undefined and matches ``predicate``.'''
        return cls.prevunknown(ui.current.address(), predicate)
    @utils.multicase(ea=six.integer_types)
    @classmethod
    def prevunknown(cls, ea):
        '''Return the previous address from ``ea`` that is undefined.'''
        return cls.prevunknown(ea, 1)
    @utils.multicase(ea=six.integer_types, predicate=builtins.callable)
    @classmethod
    def prevunknown(cls, ea, predicate):
        '''Return the previous address from ``ea`` that is undefined and matches ``predicate``.'''
        return cls.prevF(ea, type.is_unknown, 1)
    @utils.multicase(ea=six.integer_types, count=six.integer_types)
    @classmethod
    def prevunknown(cls, ea, count):
        return cls.prevF(ea, type.is_unknown, count)

    @utils.multicase()
    @classmethod
    def nextunknown(cls):
        '''Return the next address that is undefined.'''
        return cls.nextunknown(ui.current.address(), 1)
    @utils.multicase(predicate=builtins.callable)
    @classmethod
    def nextunknown(cls, predicate):
        '''Return the next address that is undefined and matches ``predicate``.'''
        return cls.nextunknown(ui.current.address(), predicate)
    @utils.multicase(ea=six.integer_types)
    @classmethod
    def nextunknown(cls, ea):
        '''Return the next address from ``ea`` that is undefined.'''
        return cls.nextunknown(ea, 1)
    @utils.multicase(ea=six.integer_types, predicate=builtins.callable)
    @classmethod
    def nextunknown(cls, ea, predicate):
        '''Return the next address from ``ea`` that is undefined and matches ``predicate``.'''
        return cls.nextF(ea, type.is_unknown, 1)
    @utils.multicase(ea=six.integer_types, count=six.integer_types)
    @classmethod
    def nextunknown(cls, ea, count):
        return cls.nextF(ea, type.is_unknown, count)

a = addr = address  # XXX: ns alias

prev, next = utils.alias(address.prev, 'address'), utils.alias(address.next, 'address')
prevref, nextref = utils.alias(address.prevref, 'address'), utils.alias(address.nextref, 'address')
prevreg, nextreg = utils.alias(address.prevreg, 'address'), utils.alias(address.nextreg, 'address')

class type(object):
    """
    Namespace for fetching type information from the different addresses
    defined within the database. The functions within this namespace allow
    one to extract various type information from the different locations
    within the database.

    This namespace is also aliased as `database.t`.

    By default, this namespace will return the `idaapi.DT_TYPE` of the
    specified address.
    """

    @utils.multicase()
    def __new__(cls):
        '''Return the type at the address specified at the current address.'''
        ea = ui.current.address()
        return cls(ea)
    @utils.multicase(ea=six.integer_types)
    def __new__(cls, ea):
        '''Return the type at the address specified by ``ea``.'''
        return cls.flags(ea, idaapi.DT_TYPE)

    @utils.multicase()
    @classmethod
    def size(cls):
        '''Returns the size of the item at the current address.'''
        return size(ui.current.address())
    @utils.multicase(ea=six.integer_types)
    @classmethod
    def size(cls, ea):
        '''Returns the size of the item at the address ``ea``.'''
        ea = interface.address.within(ea)
        return idaapi.get_item_size(ea)

    @utils.multicase()
    @classmethod
    def flags(cls):
        '''Returns the flags of the item at the current address.'''
        return cls.flags(ui.current.address())
    @utils.multicase(ea=six.integer_types)
    @classmethod
    def flags(cls, ea):
        '''Returns the flags of the item at the address ``ea``.'''
        getflags = idaapi.getFlags if idaapi.__version__ < 7.0 else idaapi.get_full_flags
        return getflags(interface.address.within(ea))
    @utils.multicase(ea=six.integer_types, mask=six.integer_types)
    @classmethod
    def flags(cls, ea, mask):
        '''Returns the flags at the address ``ea`` masked with ``mask``.'''
        getflags = idaapi.getFlags if idaapi.__version__ < 7.0 else idaapi.get_full_flags
        return getflags(interface.address.within(ea)) & mask
    @utils.multicase(ea=six.integer_types, mask=six.integer_types, value=six.integer_types)
    @classmethod
    def flags(cls, ea, mask, value):
        '''Sets the flags at the address ``ea`` masked with ``mask`` set to ``value``.'''
        if idaapi.__version__ < 7.0:
            ea = interface.address.within(ea)
            res = idaapi.getFlags(ea)
            idaapi.setFlags(ea, (res&~mask) | value)
            return res & mask
        raise DeprecationWarning("{:s}.flags({:#x}, {:#x}, {:d}) : IDA 7.0 has unfortunately deprecated idaapi.setFlags(...).".format('.'.join((__name__, cls.__name__)), ea, mask, value))

    @utils.multicase()
    @staticmethod
    def is_initialized():
        '''Return `True` if the current address is initialized.'''
        return type.is_initialized(ui.current.address())
    @utils.multicase(ea=six.integer_types)
    @staticmethod
    def is_initialized(ea):
        '''Return `True` if the address specified by ``ea`` is initialized.'''
        return type.flags(interface.address.within(ea), idaapi.FF_IVL) == idaapi.FF_IVL
    initializedQ = utils.alias(is_initialized, 'type')

    @utils.multicase()
    @staticmethod
    def is_code():
        '''Return `True` if the current address is marked as code.'''
        return type.is_code(ui.current.address())
    @utils.multicase(ea=six.integer_types)
    @staticmethod
    def is_code(ea):
        '''Return `True` if the address specified by ``ea`` is marked as code.'''
        return type.flags(interface.address.within(ea), idaapi.MS_CLS) == idaapi.FF_CODE
    codeQ = utils.alias(is_code, 'type')

    @utils.multicase()
    @staticmethod
    def is_data():
        '''Return `True` if the current address is marked as data.'''
        return type.is_data(ui.current.address())
    @utils.multicase(ea=six.integer_types)
    @staticmethod
    def is_data(ea):
        '''Return `True` if the address specified by ``ea`` is marked as data.'''
        return type.flags(interface.address.within(ea), idaapi.MS_CLS) == idaapi.FF_DATA
    dataQ = utils.alias(is_data, 'type')

    # True if ea marked unknown
    @utils.multicase()
    @staticmethod
    def is_unknown():
        '''Return `True` if the current address is undefined.'''
        return type.is_unknown(ui.current.address())
    @utils.multicase(ea=six.integer_types)
    @staticmethod
    def is_unknown(ea):
        '''Return `True` if the address specified by ``ea`` is undefined.'''
        return type.flags(interface.address.within(ea), idaapi.MS_CLS) == idaapi.FF_UNK
    unknownQ = undefined = utils.alias(is_unknown, 'type')

    @utils.multicase()
    @staticmethod
    def is_head():
        '''Return `True` if the current address is aligned to a definition in the database.'''
        return type.is_head(ui.current.address())
    @utils.multicase(ea=six.integer_types)
    @staticmethod
    def is_head(ea):
        '''Return `True` if the address ``ea`` is aligned to a definition in the database.'''
        return type.flags(interface.address.within(ea), idaapi.FF_DATA) != 0
    headQ = utils.alias(is_head, 'type')

    @utils.multicase()
    @staticmethod
    def is_tail():
        '''Return `True` if the current address is not-aligned to a definition in the database.'''
        return type.is_tail(ui.current.address())
    @utils.multicase(ea=six.integer_types)
    @staticmethod
    def is_tail(ea):
        '''Return `True` if the address ``ea`` is not-aligned to a definition in the database.'''
        return type.flags(interface.address.within(ea), idaapi.MS_CLS) == idaapi.FF_TAIL
    tailQ = utils.alias(is_tail, 'type')

    @utils.multicase()
    @staticmethod
    def is_align():
        '''Return `True` if the current address is defined as an alignment.'''
        return type.is_align(ui.current.address())
    @utils.multicase(ea=six.integer_types)
    @staticmethod
    def is_align(ea):
        '''Return `True` if the address at ``ea`` is defined as an alignment.'''
        return idaapi.isAlign(type.flags(ea))
    alignQ = utils.alias(is_align, 'type')

    @utils.multicase()
    @staticmethod
    def has_comment():
        '''Return `True` if the current address is commented.'''
        return type.has_comment(ui.current.address())
    @utils.multicase(ea=six.integer_types)
    @staticmethod
    def has_comment(ea):
        '''Return `True` if the address at ``ea`` is commented.'''
        return type.flags(interface.address.within(ea), idaapi.FF_COMM) == idaapi.FF_COMM
    commentQ = utils.alias(has_comment, 'type')

    @utils.multicase()
    @staticmethod
    def has_reference():
        '''Return `True` if the current address has a reference.'''
        return type.has_reference(ui.current.address())
    @utils.multicase(ea=six.integer_types)
    @staticmethod
    def has_reference(ea):
        '''Return `True` if the address at ``ea`` has a reference.'''
        return type.flags(interface.address.within(ea), idaapi.FF_REF) == idaapi.FF_REF
    referenceQ = refQ = utils.alias(has_reference, 'type')

    @utils.multicase()
    @staticmethod
    def has_label():
        '''Return `True` if the current address has a label.'''
        return type.has_label(ui.current.address())
    @utils.multicase(ea=six.integer_types)
    @staticmethod
    def has_label(ea):
        '''Return `True` if the address at ``ea`` has a label.'''
        return idaapi.has_any_name(type.flags(ea))
    labelQ = nameQ = has_name = utils.alias(has_label, 'type')

    @utils.multicase()
    @staticmethod
    def has_customname():
        '''Return `True` if the current address has a custom-name.'''
        return type.has_customname(ui.current.address())
    @utils.multicase(ea=six.integer_types)
    @staticmethod
    def has_customname(ea):
        '''Return `True` if the address at ``ea`` has a custom-name.'''
        return type.flags(interface.address.within(ea), idaapi.FF_NAME) == idaapi.FF_NAME
    customnameQ = utils.alias(has_customname, 'type')

    @utils.multicase()
    @staticmethod
    def has_dummyname():
        '''Return `True` if the current address has a dummy-name.'''
        return type.has_dummyname(ui.current.address())
    @utils.multicase(ea=six.integer_types)
    @staticmethod
    def has_dummyname(ea):
        '''Return `True` if the address at ``ea`` has a dummy-name.'''
        return type.flags(ea, idaapi.FF_LABL) == idaapi.FF_LABL
    dummynameQ = utils.alias(has_dummyname, 'type')

    @utils.multicase()
    @staticmethod
    def has_autoname():
        '''Return `True` if the current address is automatically named.'''
        return type.has_autoname(ui.current.address())
    @utils.multicase(ea=six.integer_types)
    @staticmethod
    def has_autoname(ea):
        '''Return `True` if the address ``ea`` is automatically named.'''
        return idaapi.has_auto_name(type.flags(ea))
    autonameQ = utils.alias(has_autoname, 'type')

    @utils.multicase()
    @staticmethod
    def has_publicname():
        '''Return `True` if the current address has a public name.'''
        return type.has_publicname(ui.current.address())
    @utils.multicase(ea=six.integer_types)
    @staticmethod
    def has_publicname(ea):
        '''Return `True` if the address at ``ea`` has a public name.'''
        return idaapi.is_public_name(interface.address.within(ea))
    publicnameQ = utils.alias(has_publicname, 'type')

    @utils.multicase()
    @staticmethod
    def has_weakname():
        '''Return `True` if the current address has a weakly-typed name.'''
        return type.has_weakname(ui.current.address())
    @utils.multicase(ea=six.integer_types)
    @staticmethod
    def has_weakname(ea):
        '''Return `True` if the address at ``ea`` has a weakly-typed name.'''
        return idaapi.is_weak_name(interface.address.within(ea))
    weaknameQ = utils.alias(has_weakname, 'type')

    @utils.multicase()
    @staticmethod
    def has_listedname():
        '''Return `True` if the current address has a name that is listed.'''
        return type.has_listedname(ui.current.address())
    @utils.multicase(ea=six.integer_types)
    @staticmethod
    def has_listedname(ea):
        '''Return `True` if the address at ``ea`` has a name that is listed.'''
        return idaapi.is_in_nlist(interface.address.within(ea))
    listednameQ = utils.alias(has_listedname, 'type')

    @utils.multicase()
    @staticmethod
    def is_label():
        '''Return `True` if the current address has a label.'''
        return type.is_label(ui.current.address())
    @utils.multicase(ea=six.integer_types)
    @staticmethod
    def is_label(ea):
        '''Return `True` if the address at ``ea`` has a label.'''
        return type.has_dummyname(ea) or type.has_customname(ea)
    labelQ = utils.alias(is_label, 'type')

    class array(object):
        """
        Namespace for returning type information about an array that is defined
        within the database. By default this namespace will return the array's
        element size and number of elements as a tuple (size, count).
        """
        @utils.multicase()
        def __new__(cls):
            '''Return the array's (element, length) at the current address.'''
            return cls(ui.current.address())
        @utils.multicase(ea=six.integer_types)
        def __new__(cls, ea):
            '''Return the array's (element, length) at the address specified by ``ea``.'''
            return cls.element(ea), cls.length(ea)

        @utils.multicase()
        @classmethod
        def element(cls):
            '''Return the size of an element in the array at the current address.'''
            return cls.element(ui.current.address())
        @utils.multicase(ea=six.integer_types)
        @classmethod
        def element(cls, ea):
            '''Return the size of an element in the array at address ``ea``.'''
            ea, F, T = interface.address.within(ea), type.flags(ea), type.flags(ea, idaapi.DT_TYPE)
            return _structure.size(type.structure.id(ea)) if T == idaapi.FF_STRU else idaapi.get_full_data_elsize(ea, F)

        @utils.multicase()
        @classmethod
        def length(cls):
            '''Return the number of elements of the array at the current address.'''
            return cls.length(ui.current.address())
        @utils.multicase(ea=six.integer_types)
        @classmethod
        def length(cls, ea):
            '''Return the number of elements in the array at address ``ea``.'''
            ea, F = interface.address.within(ea), type.flags(ea)
            sz,ele = idaapi.get_item_size(ea),idaapi.get_full_data_elsize(ea, F)
            return sz // ele

        @utils.multicase()
        @classmethod
        def size(cls):
            '''Return the total size of the array at the current address.'''
            return type.size(ui.current.address())
        @utils.multicase(ea=six.integer_types)
        @classmethod
        def size(cls, ea):
            '''Return the total size of the array at address ``ea``.'''
            return type.size(ea)

    class structure(object):
        """
        Namespace for returning type information about a structure that is defined
        within the database. By default this namespace will return the `structure_t`
        at the given address.
        """
        @utils.multicase()
        def __new__(cls):
            '''Return the structure type at the current address.'''
            return cls(ui.current.address())
        @utils.multicase(ea=six.integer_types)
        def __new__(cls, ea):
            '''Return the structure type at address ``ea``.'''
            res = cls.id(ea)
            return _structure.by(res)

        @utils.multicase()
        @classmethod
        def id(cls):
            '''Return the identifier of the structure at the current address.'''
            return cls.id(ui.current.address())
        @utils.multicase(ea=six.integer_types)
        @classmethod
        def id(cls, ea):
            '''Return the identifier of the structure at address ``ea``.'''
            ea = interface.address.within(ea)

            res = type.flags(ea, idaapi.DT_TYPE)
            if res != idaapi.FF_STRU:
                raise TypeError("{:s}.id({:#x}) : type at specified locatiopn is not an FF_STRU({:#x}) : {:#x}".format('.'.join((__name__, 'type', 'structure')), ea, idaapi.FF_STRU, res))

            ti, F = idaapi.opinfo_t(), type.flags(ea)
            res = idaapi.get_opinfo(ea, 0, F, ti)
            if not res:
                raise ValueError("{:s}.id({:#x}) : idaapi.get_opinfo returned {:#x} at {:#x}".format('.'.join((__name__, 'type', 'structure')), ea, res, ea))
            return ti.tid

        @utils.multicase()
        @classmethod
        def size(cls):
            '''Return the total size of the structure at the current address.'''
            return type.size(ui.current.address())
        @utils.multicase(ea=six.integer_types)
        @classmethod
        def size(cls, ea):
            '''Return the total size of the structure at address ``ea``.'''
            return type.size(ea)
    struc = struct = structure  # ns alias

    @utils.multicase()
    @classmethod
    def switch(cls):
        '''Return the switch_t at the current address.'''
        return get.switch(ui.current.address())
    @utils.multicase(ea=six.integer_types)
    @classmethod
    def switch(cls, ea):
        '''Return the switch_t at the address ``ea``.'''
        return get.switch(ea)

    @utils.multicase()
    @staticmethod
    def is_importref():
        '''Returns `True` if the instruction at the current address references an import.'''
        return type.is_importref(ui.current.address())
    @utils.multicase(ea=six.integer_types)
    @staticmethod
    def is_importref(ea):
        '''Returns `True` if the instruction at ``ea`` references an import.'''
        ea = interface.address.inside(ea)

        # FIXME: this doesn't seem like the right way to determine an instruction is reffing an import
        return len(database.dxdown(ea)) == len(database.cxdown(ea)) and len(database.cxdown(ea)) > 0
    isImportRef = importrefQ = utils.alias(is_importref, 'type')

    @utils.multicase()
    @staticmethod
    def is_globalref():
        '''Returns `True` if the instruction at the current address references a global.'''
        return is_globalref(ui.current.address())
    @utils.multicase(ea=six.integer_types)
    @staticmethod
    def is_globalref(ea):
        '''Returns `True` if the instruction at ``ea`` references a global.'''
        ea = interface.address.inside(ea)

        # FIXME: this doesn't seem like the right way to determine this...
        return len(database.dxdown(ea)) > len(database.cxdown(ea))
    isGlobalRef = globalrefQ = utils.alias(is_globalref, 'type')

t = type    # XXX: ns alias

## information about a given address
size = utils.alias(type.size, 'type')
is_code = utils.alias(type.is_code, 'type')
is_data = utils.alias(type.is_data, 'type')
is_unknown = utils.alias(type.is_unknown, 'type')
is_head = utils.alias(type.is_head, 'type')
is_tail = utils.alias(type.is_tail, 'type')
is_align = utils.alias(type.is_align, 'type')
getType = get_type = utils.alias(type.__new__, 'type')

# arrays
getSize = get_size = utils.alias(type.array.element, 'type.array')
getArrayLength = get_arraylength = utils.alias(type.array.length, 'type.array')

# structures
getStructureId = get_strucid = get_structureid = utils.alias(type.structure.id, 'type.structure')

class xref(object):
    """
    Namespace for navigating the cross-references (xrefs) associated with an
    address in the database. This lets one identify code xrefs from data xrefs
    and even allows one to add or remove xrefs as they see fit.

    This namespace is also aliased as `database.x`.

    Some of the more common functions are used so often that they're also
    aliased as globals. Some of these are:
        `database.up` - Return all addresses that reference an address
        `database.down` - Return all addresses that an address references
        `database.drefs` - Return all the data references for an address
        `database.crefs` - Return all the code references for an address
        `database.dxup` - Return all the data references that reference an address
        `database.dxdown` - Return all the data references that an address references
        `database.cxup` - Return all the code references that reference an address
        `database.cxdown` - Return all the code references that an address references
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
        '''Return all of the code xrefs that refer to the address ``ea``.'''
        return xref.code(ea, False)
    @utils.multicase(ea=six.integer_types, descend=bool)
    @staticmethod
    def code(ea, descend):
        """Return all of the code xrefs that refer to the address ``ea``.

        If the bool ``descend`` is defined, then return only code refs that are referred by the specified address.
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
        '''Return all of the data xrefs that refer to the address ``ea``.'''
        return xref.data(ea, False)
    @utils.multicase(ea=six.integer_types, descend=bool)
    @staticmethod
    def data(ea, descend):
        """Return all of the data xrefs that refer to the address ``ea``.

        If the bool ``descend`` is defined, then return only the data refs that are referred by the specified address.
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
        '''Return all of the data xrefs that are referenced by the address ``ea``.'''
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
        '''Return all of the data xrefs that refer to the address ``ea``.'''
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
        '''Return all of the code xrefs that are referenced by the address ``ea``.'''
        result = builtins.set(xref.code(ea, True))
        result.discard(address.next(ea))
        return sorted(result)
    cd = utils.alias(code_down, 'xref')

    @utils.multicase()
    @staticmethod
    def code_up():
        '''Return all of the code xrefs that are referenced by the current address.'''
        return xref.code_up(ui.current.address())
    @utils.multicase(ea=six.integer_types)
    @staticmethod
    def code_up(ea):
        '''Return all of the code xrefs that refer to the address ``ea``.'''
        result = builtins.set(xref.code(ea, False))
        result.discard(address.prev(ea))
        return sorted(result)
    cu = utils.alias(code_up, 'xref')

    @utils.multicase()
    @staticmethod
    def up():
        '''Return all of the references that refer to the current address.'''
        return xref.up(ui.current.address())
    @utils.multicase(ea=six.integer_types)
    @staticmethod
    def up(ea):
        '''Return all of the references that refer to the address ``ea``.'''
        return sorted(builtins.set(xref.data_up(ea) + xref.code_up(ea)))
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
        '''Return all of the references that are referred by the address ``ea``.'''
        return sorted(builtins.set(xref.data_down(ea) + xref.code_down(ea)))
    d = utils.alias(down, 'xref')

    @utils.multicase(target=six.integer_types)
    @staticmethod
    def add_code(target, **reftype):
        '''Add a code reference from the current address to ``target``.'''
        return xref.add_code(ui.current.address(), target, **reftype)
    @utils.multicase(six=six.integer_types, target=six.integer_types)
    @staticmethod
    def add_code(ea, target, **reftype):
        """Add a code reference from address ``ea`` to ``target``.

        If the reftype ``call`` is `True`, then specify this ref as a function call.
        """
        ea, target = interface.address.inside(ea, target)

        isCall = builtins.next((reftype[k] for k in ('call', 'is_call', 'isCall', 'iscall', 'callQ') if k in reftype), None)
        if abs(target-ea) > 2**(config.bits()/2):
            flowtype = idaapi.fl_CF if isCall else idaapi.fl_JF
        else:
            flowtype = idaapi.fl_CN if isCall else idaapi.fl_JN
        idaapi.add_cref(ea, target, flowtype | idaapi.XREF_USER)
        return target in xref.code_down(ea)
    ac = utils.alias(add_code, 'xref')

    @utils.multicase(target=six.integer_types)
    @staticmethod
    def add_data(target, **reftype):
        '''Add a data reference from the current address to ``target``.'''
        return xref.add_data(ui.current.address(), target, **reftype)
    @utils.multicase(ea=six.integer_types, target=six.integer_types)
    @staticmethod
    def add_data(ea, target, **reftype):
        """Add a data reference from the address ``ea`` to ``target``.

        If the reftype ``write`` is `True`, then specify that this ref is writing to the target.
        """
        ea, target = interface.address.inside(ea, target)
        isWrite = reftype.get('write', False)
        flowtype = idaapi.dr_W if isWrite else idaapi.dr_R
        idaapi.add_dref(ea, target, flowtype | idaapi.XREF_USER)
        return target in xref.data_down(ea)
    ad = utils.alias(add_data, 'xref')

    @utils.multicase(ea=six.integer_types)
    @staticmethod
    def del_code(ea):
        '''Delete _all_ the code references at ``ea``.'''
        ea = interface.address.inside(ea)
        [ idaapi.del_cref(ea, target, 0) for target in xref.code_down(ea) ]
        return False if len(xref.code_down(ea)) > 0 else True
    @utils.multicase(ea=six.integer_types, target=six.integer_types)
    @staticmethod
    def del_code(ea, target):
        '''Delete any code references at ``ea`` that point to address ``target``.'''
        ea = interface.address.inside(ea)
        idaapi.del_cref(ea, target, 0)
        return target not in xref.code_down(ea)

    @utils.multicase(ea=six.integer_types)
    @staticmethod
    def del_data(ea):
        '''Delete _all_ the data references at ``ea``.'''
        ea = interface.address.inside(ea)
        [ idaapi.del_dref(ea, target) for target in xref.data_down(ea) ]
        return False if len(xref.data_down(ea)) > 0 else True
    @utils.multicase(ea=six.integer_types, target=six.integer_types)
    @staticmethod
    def del_data(ea, target):
        '''Delete any data references at ``ea`` that point to address ``target``.'''
        ea = interface.address.inside(ea)
        idaapi.del_dref(ea, target)
        return target not in xref.data_down(ea)

    @staticmethod
    def clear(ea):
        '''Clear all references at the address ``ea``.'''
        ea = interface.address.inside(ea)
        return all(ok for ok in (xref.del_code(ea), xref.del_data(ea)))
x = xref    # XXX: ns alias

drefs, crefs = utils.alias(xref.data, 'xref'), utils.alias(xref.code, 'xref')
dxdown, dxup = utils.alias(xref.data_down, 'xref'), utils.alias(xref.data_up, 'xref')
cxdown, cxup = utils.alias(xref.code_down, 'xref'), utils.alias(xref.code_up, 'xref')
up, down = utils.alias(xref.up, 'xref'), utils.alias(xref.down, 'xref')

# create/erase a mark at the specified address in the .idb
class marks(object):
    """
    Namespace for interacting with the marks table within the database. By
    default, this namespace yields the (address, description) of each mark
    within the database.

    This allows one to manage the marks. Although it is suggested to utilize
    "tags" as they provide significantly more flexibility. Using marks allows
    for one to use IDA's mark window for quick navigation to a mark.
    """
    MAX_SLOT_COUNT = 0x400
    table = {}

    # FIXME: implement a matcher class for this too
    def __new__(cls):
        '''Yields each of the marked positions within the database.'''
        res = builtins.list(cls.iterate()) # make a copy in-case someone is actively modifying it
        for ea, comment in cls.iterate():
            yield ea, comment
        return

    @utils.multicase(description=basestring)
    @classmethod
    def new(cls, description):
        '''Create a mark at the current address with the given ``description``.'''
        return cls.new(ui.current.address(), description)
    @utils.multicase(ea=six.integer_types, description=basestring)
    @classmethod
    def new(cls, ea, description, **extra):
        '''Create a mark at the address ``ea`` with the given ``description`` and return its index.'''
        ea = interface.address.inside(ea)
        try:
            idx = cls.__find_slotaddress(ea)
            ea, res = cls.by_index(idx)
            logging.warn("{:s}.new({:#x}, ...) : Replacing mark {:d} at {:#x} : {!r} -> {!r}".format('.'.join((__name__, cls.__name__)), ea, idx, ea, res, description))
        except KeyError:
            res, idx = None, cls.__free_slotindex()
            logging.info("{:s}.new({:#x}, ...) : Creating mark {:d} at {:#x} : {!r}".format('.'.join((__name__, cls.__name__)), ea, idx, ea, description))
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
        '''Remove the mark at the specified address ``ea`` returning the previous description.'''
        ea = interface.address.inside(ea)
        idx = cls.__find_slotaddress(ea)
        descr = cls.__get_description(idx)
        cls.__set_description(idx, ea, '')
        logging.warn("{:s}.remove({:#x}) : Removed mark {:d} at {:#x} : {!r}".format('.'.join((__name__, cls.__name__)), ea, idx, ea, descr))
        return descr

    @classmethod
    def iterate(cls):
        '''Iterate through all of the marks in the database.'''
        count = 0
        try:
            for idx in six.moves.range(cls.MAX_SLOT_COUNT):
                yield cls.by_index(idx)
        except KeyError:
            pass
        return

    @classmethod
    def length(cls):
        '''Return the number of marks in the database.'''
        return len(builtins.list(cls.iterate()))

    @classmethod
    def by_index(cls, index):
        '''Return the (address, description) of the mark at the specified ``index`` in the mark list.'''
        if 0 <= index < cls.MAX_SLOT_COUNT:
            return (cls.__get_slotaddress(index), cls.__get_description(index))
        raise KeyError("{:s}.by_index({:d}) : Mark slot index is out of bounds. : {:s}".format('.'.join((__name__, cls.__name__)), index, ("{:d} < 0".format(index)) if index < 0 else ("{:d} >= MAX_SLOT_COUNT".format(index))))
    byIndex = utils.alias(by_index, 'marks')

    @utils.multicase()
    @classmethod
    def by_address(cls):
        '''Return the mark at the current address.'''
        return cls.by_address(ui.current.address())
    @utils.multicase(ea=six.integer_types)
    @classmethod
    def by_address(cls, ea):
        '''Return the (address, description) of the mark at the given address ``ea``.'''
        return cls.by_index(cls.__find_slotaddress(ea))
    by = byAddress = utils.alias(by_address, 'marks')

    ## Internal functions depending on which version of IDA is being used (<7.0)
    if idaapi.__version__ < 7.0:
        @classmethod
        def __location(cls, **attrs):
            '''Return a location_t object with the specified attributes.'''
            res = idaapi.curloc()
            builtins.list(itertools.starmap(functools.partial(setattr, res), attrs.items()))
            return res

        @classmethod
        def __set_description(cls, index, ea, description, **extra):
            '''Modify the mark at ``index`` to point to the address ``ea`` with the specified ``description``.'''
            res = cls.__location(ea=ea, x=extra.get('x', 0), y=extra.get('y', 0), lnnum=extra.get('y', 0))
            title, descr = description, description
            res.mark(index, title, descr)
            #raise KeyError("{:s}.set_description({:d}, {:#x}, {!r}{:s}) : Unable to get slot address for specified index.".format('.'.join((__name__, cls.__name__)), index, ea, description, ", {:s}".format(', '.join(itertools.imap(utils.unbox("{:s}={!r}".format), six.iteritems(extra))) if extra else '')))
            return index

        @classmethod
        def __get_description(cls, index):
            '''Return the description of the mark at the specified ``index``.'''
            return cls.__location().markdesc(index)

        @classmethod
        def __find_slotaddress(cls, ea):
            '''Return the index of the mark at the specified address ``ea``.'''
            # FIXME: figure out how to fail if this address isn't found
            res = itertools.islice(itertools.count(), cls.MAX_SLOT_COUNT)
            res, iterable = itertools.tee(itertools.imap(cls.__get_slotaddress, res))
            try:
                count = len(builtins.list(itertools.takewhile(lambda n: n != ea, res)))
            except IndexError:
                raise KeyError("{:s}.find_slotaddress({:#x}) : Unable to find specified slot address.".format('.'.join((__name__, cls.__name__)), ea))
            builtins.list(itertools.islice(iterable, count))
            if builtins.next(iterable) != ea:
                raise KeyError("{:s}.find_slotaddress({:#x}) : Unable to find specified slot address.".format('.'.join((__name__, cls.__name__)), ea))
            return count

        @classmethod
        def __free_slotindex(cls):
            '''Return the index of the next available mark slot.'''
            return cls.length()

        @classmethod
        def __get_slotaddress(cls, index):
            '''Return the address of the mark at the specified ``index``.'''
            loc = cls.__location()
            intp = idaapi.int_pointer()
            intp.assign(index)
            res = loc.markedpos(intp)
            if res == idaapi.BADADDR:
                raise KeyError("{:s}.get_slotaddress({:d}) : Unable to get slot address for specified index.".format('.'.join((__name__, cls.__name__)), index))
            return address.head(res)

    ## Internal functions depending on which version of IDA is being used (>= 7.0)
    else:
        @classmethod
        def __set_description(cls, index, ea, description, **extra):
            '''Modify the mark at ``index`` to point to the address ``ea`` with the specified ``description``.'''
            idaapi.mark_position(ea, extra.get('lnnum', 0), extra.get('x', 0), extra.get('y', 0), index, description)
            #raise KeyError("{:s}.set_description({:d}, {:#x}, {!r}{:s}) : Unable to get slot address for specified index.".format('.'.join((__name__, cls.__name__)), index, ea, description, ", {:s}".format(', '.join(itertools.imap(utils.unbox("{:s}={!r}".format), six.iteritems(extra)))) if extra else ''))
            return index

        @classmethod
        def __get_description(cls, index):
            '''Return the description of the mark at the specified ``index``.'''
            return idaapi.get_mark_comment(index)

        @classmethod
        def __find_slotaddress(cls, ea):
            '''Return the index of the mark at the specified address ``ea``.'''
            res = itertools.islice(itertools.count(), cls.MAX_SLOT_COUNT)
            res, iterable = itertools.tee(itertools.imap(cls.__get_slotaddress, res))
            try:
                count = len(builtins.list(itertools.takewhile(lambda n: n != ea, res)))
            except IndexError:
                raise KeyError("{:s}.find_slotaddress({:#x}) : Unable to find specified slot address.".format('.'.join((__name__, cls.__name__)), ea))
            builtins.list(itertools.islice(iterable, count))
            if builtins.next(iterable) != ea:
                raise KeyError("{:s}.find_slotaddress({:#x}) : Unable to find specified slot address.".format('.'.join((__name__, cls.__name__)), ea))
            return count

        @classmethod
        def __free_slotindex(cls):
            '''Return the index of the next available mark slot.'''
            res = builtins.next((i for i in six.moves.range(cls.MAX_SLOT_COUNT) if idaapi.get_marked_pos(i) == idaapi.BADADDR), None)
            if res is None:
                raise ValueError("{:s}.free_slotindex : No free slots available for mark.".format('.'.join((__name__, 'bookmarks', cls.__name__))))
            return res

        @classmethod
        def __get_slotaddress(cls, index):
            '''Get the address of the mark at index ``index``.'''
            res = idaapi.get_marked_pos(index)
            if res == idaapi.BADADDR:
                raise KeyError("{:s}.get_slotaddress({:d}) : Unable to get slot address for specified index.".format('.'.join((__name__, cls.__name__)), index))
            return address.head(res)

@utils.multicase()
def mark():
    '''Return the mark at the current address.'''
    _, res = marks.by_address(ui.current.address())
    return res
@utils.multicase(none=types.NoneType)
def mark(none):
    '''Remove the mark at the current address.'''
    return mark(ui.current.address(), None)
@utils.multicase(ea=six.integer_types)
def mark(ea):
    '''Return the mark at the specified address ``ea``.'''
    _, res = marks.by_address(ea)
    return res
@utils.multicase(description=basestring)
def mark(description):
    '''Set the mark at the current address to the specified ``description``.'''
    return mark(ui.current.address(), description)
@utils.multicase(ea=six.integer_types, none=types.NoneType)
def mark(ea, none):
    '''Erase the mark at address ``ea``.'''
    try: tag(ea, 'mark', None)
    except KeyError: pass
    color(ea, None)
    return marks.remove(ea)
@utils.multicase(ea=six.integer_types, description=basestring)
def mark(ea, description):
    '''Sets the mark at address ``ea`` to the specified ``description``.'''
    return marks.new(ea, description)

class extra(object):
    """
    Namespace for interacting with IDA's "extra" comments that can be
    associated with an address. This allows one to prefix or suffix an
    address with a large block of text simulating a paragraph.
    """

    MAX_ITEM_LINES = 5000   # defined in cfg/ida.cfg according to python/idc.py
    MAX_ITEM_LINES = (idaapi.E_NEXT-idaapi.E_PREV) if idaapi.E_NEXT > idaapi.E_PREV else idaapi.E_PREV-idaapi.E_NEXT

    @classmethod
    def __has_extra__(cls, ea, base):
        sup = internal.netnode.sup
        return sup.get(ea, base) is not None

    @utils.multicase()
    @classmethod
    def has_prefix(cls):
        '''Returns `True` if the item at the current address has extra prefix lines.'''
        return cls.__has_extra__(ui.current.address(), idaapi.E_PREV)
    @utils.multicase()
    @classmethod
    def has_suffix(cls):
        '''Returns `True` if the item at the current address has extra suffix lines.'''
        return cls.__has_extra__(ui.current.address(), idaapi.E_NEXT)
    @utils.multicase(ea=six.integer_types)
    @classmethod
    def has_prefix(cls, ea):
        '''Returns `True` if the item at the address ``ea`` has extra prefix lines.'''
        return cls.__has_extra__(ea, idaapi.E_PREV)
    @utils.multicase(ea=six.integer_types)
    @classmethod
    def has_suffix(cls, ea):
        '''Returns `True` if the item at the address ``ea`` has extra suffix lines.'''
        return cls.__has_extra__(ea, idaapi.E_NEXT)
    prefixQ, suffixQ = utils.alias(has_prefix, 'extra'), utils.alias(has_suffix, 'extra')

    @classmethod
    def __count__(cls, ea, base):
        sup = internal.netnode.sup
        for i in six.moves.range(cls.MAX_ITEM_LINES):
            row = sup.get(ea, base+i)
            if row is None: break
        return i or None

    if idaapi.__version__ < 7.0:
        @classmethod
        def __hide__(cls, ea):
            if type.flags(ea, idaapi.FF_LINE) == idaapi.FF_LINE:
                type.flags(ea, idaapi.FF_LINE, 0)
                return True
            return False

        @classmethod
        def __show__(cls, ea):
            if type.flags(ea, idaapi.FF_LINE) != idaapi.FF_LINE:
                type.flags(ea, idaapi.FF_LINE, idaapi.FF_LINE)  # FIXME: IDA 7.0 : ida_nalt.set_visible_item?
                return True
            return False

        @classmethod
        def __get__(cls, ea, base):
            sup = internal.netnode.sup
            count = cls.__count__(ea, base)
            if count is None: return None
            res = (sup.get(ea, base+i) for i in six.moves.range(count))
            return '\n'.join(row[:-1] if row.endswith('\x00') else row for row in res)
        @classmethod
        def __set__(cls, ea, string, base):
            cls.__hide__(ea)
            sup = internal.netnode.sup
            [ sup.set(ea, base+i, row+'\x00') for i, row in enumerate(string.split('\n')) ]
            cls.__show__(ea)
            return True
        @classmethod
        def __del__(cls, ea, base):
            sup = internal.netnode.sup
            count = cls.__count__(ea, base)
            if count is None: return False
            cls.__hide__(ea)
            [ sup.remove(ea, base+i) for i in six.moves.range(count) ]
            cls.__show__(ea)
            return True
    else:
        @classmethod
        def __get__(cls, ea, base):
            count = cls.__count__(ea, base)
            if count is None: return None
            res = (idaapi.get_extra_cmt(ea, base+i) or '' for i in six.moves.range(count))
            return '\n'.join(res)
        @classmethod
        def __set__(cls, ea, string, base):
            [ idaapi.update_extra_cmt(ea, base+i, row) for i, row in enumerate(string.split('\n')) ]
            return string.count('\n')
        @classmethod
        def __del__(cls, ea, base):
            res = cls.__count__(ea, base)
            if res is None: return 0
            [idaapi.del_extra_cmt(ea, base+i) for i in six.moves.range(res)]
            return res

    @utils.multicase(ea=six.integer_types)
    @classmethod
    def get_prefix(cls, ea):
        '''Return the prefixed comment at address ``ea``.'''
        return cls.__get__(ea, idaapi.E_PREV)

    @utils.multicase(ea=six.integer_types)
    @classmethod
    def get_suffix(cls, ea):
        '''Return the suffixed comment at address ``ea``.'''
        return cls.__get__(ea, idaapi.E_NEXT)

    @utils.multicase(ea=six.integer_types)
    @classmethod
    def del_prefix(cls, ea):
        '''Delete the prefixed comment at address ``ea``.'''
        res = cls.__get__(ea, idaapi.E_PREV)
        cls.__del__(ea, idaapi.E_PREV)
        return res
    @utils.multicase(ea=six.integer_types)
    @classmethod
    def del_suffix(cls, ea):
        '''Delete the suffixed comment at address ``ea``.'''
        res = cls.__get__(ea, idaapi.E_NEXT)
        cls.__del__(ea, idaapi.E_NEXT)
        return res

    @utils.multicase(ea=six.integer_types, string=basestring)
    @classmethod
    def set_prefix(cls, ea, string):
        '''Set the prefixed comment at address ``ea`` to the specified ``string``.'''
        res, ok = cls.del_prefix(ea), cls.__set__(ea, string, idaapi.E_PREV)
        ok = cls.__set__(ea, string, idaapi.E_PREV)
        return res
    @utils.multicase(ea=six.integer_types, string=basestring)
    @classmethod
    def set_suffix(cls, ea, string):
        '''Set the suffixed comment at address ``ea`` to the specified ``string``.'''
        res, ok = cls.del_suffix(ea), cls.__set__(ea, string, idaapi.E_NEXT)
        return res

    @utils.multicase()
    @classmethod
    def get_prefix(cls):
        '''Return the prefixed comment at the current address.'''
        return cls.get_prefix(ui.current.address())
    @utils.multicase()
    @classmethod
    def get_suffix(cls):
        '''Return the suffixed comment at the current address.'''
        return cls.get_suffix(ui.current.address())
    @utils.multicase()
    @classmethod
    def del_prefix(cls):
        '''Delete the prefixed comment at the current address.'''
        return cls.del_prefix(ui.current.address())
    @utils.multicase()
    @classmethod
    def del_suffix(cls):
        '''Delete the suffixed comment at the current address.'''
        return cls.del_suffix(ui.current.address())
    @utils.multicase(string=basestring)
    @classmethod
    def set_prefix(cls, string):
        '''Set the prefixed comment at the current address to the specified ``string``.'''
        return cls.set_prefix(ui.current.address(), string)
    @utils.multicase(string=basestring)
    @classmethod
    def set_suffix(cls, string):
        '''Set the suffixed comment at the current address to the specified ``string``.'''
        return cls.set_suffix(ui.current.address(), string)

    @utils.multicase()
    @classmethod
    def prefix(cls):
        '''Return the prefixed comment at the current address.'''
        return cls.get_prefix(ui.current.address())
    @utils.multicase(string=basestring)
    @classmethod
    def prefix(cls, string):
        '''Set the prefixed comment at the current address to the specified ``string``.'''
        return cls.set_prefix(ui.current.address(), string)
    @utils.multicase(none=types.NoneType)
    @classmethod
    def prefix(cls, none):
        '''Delete the prefixed comment at the current address.'''
        return cls.del_prefix(ui.current.address())
    @utils.multicase(ea=six.integer_types)
    @classmethod
    def prefix(cls, ea):
        '''Return the prefixed comment at address ``ea``.'''
        return cls.get_prefix(ea)
    @utils.multicase(ea=six.integer_types, string=basestring)
    @classmethod
    def prefix(cls, ea, string):
        '''Set the prefixed comment at address ``ea`` to the specified ``string``.'''
        return cls.set_prefix(ea, string)
    @utils.multicase(ea=six.integer_types, none=types.NoneType)
    @classmethod
    def prefix(cls, ea, none):
        '''Delete the prefixed comment at address ``ea``.'''
        return cls.del_prefix(ea)

    @utils.multicase()
    @classmethod
    def suffix(cls):
        '''Return the suffixed comment at the current address.'''
        return cls.get_suffix(ui.current.address())
    @utils.multicase(string=basestring)
    @classmethod
    def suffix(cls, string):
        '''Set the suffixed comment at the current address to the specified ``string``.'''
        return cls.set_suffix(ui.current.address(), string)
    @utils.multicase(none=types.NoneType)
    @classmethod
    def suffix(cls, none):
        '''Delete the suffixed comment at the current address.'''
        return cls.del_suffix(ui.current.address())
    @utils.multicase(ea=six.integer_types)
    @classmethod
    def suffix(cls, ea):
        '''Return the suffixed comment at address ``ea``.'''
        return cls.get_suffix(ea)
    @utils.multicase(ea=six.integer_types, string=basestring)
    @classmethod
    def suffix(cls, ea, string):
        '''Set the suffixed comment at address ``ea`` to the specified ``string``.'''
        return cls.set_suffix(ea, string)
    @utils.multicase(ea=six.integer_types, none=types.NoneType)
    @classmethod
    def suffix(cls, ea, none):
        '''Delete the suffixed comment at address ``ea``.'''
        return cls.del_suffix(ea)

    @classmethod
    def __insert_space(cls, ea, count, (getter, setter, remover)):
        res = getter(ea)
        lstripped, nl = ('', 0) if res is None else (res.lstrip('\n'), len(res) - len(res.lstrip('\n')) + 1)
        return setter(ea, '\n'*(nl+count-1) + lstripped) if nl + count > 0 or lstripped else remover(ea)
    @classmethod
    def __append_space(cls, ea, count, (getter, setter, remover)):
        res = getter(ea)
        rstripped, nl = ('', 0) if res is None else (res.rstrip('\n'), len(res) - len(res.rstrip('\n')) + 1)
        return setter(ea, rstripped + '\n'*(nl+count-1)) if nl + count > 0 or rstripped else remover(ea)

    @utils.multicase(ea=six.integer_types, count=six.integer_types)
    @classmethod
    def preinsert(cls, ea, count):
        '''Insert ``count`` lines in front of the item at address ``ea``.'''
        res = cls.get_prefix, cls.set_prefix, cls.del_prefix
        return cls.__insert_space(ea, count, res)
    @utils.multicase(ea=six.integer_types, count=six.integer_types)
    @classmethod
    def preappend(cls, ea, count):
        '''Append ``count`` lines in front of the item at address ``ea``.'''
        res = cls.get_prefix, cls.set_prefix, cls.del_prefix
        return cls.__append_space(ea, count, res)

    @utils.multicase(ea=six.integer_types, count=six.integer_types)
    @classmethod
    def postinsert(cls, ea, count):
        '''Insert ``count`` lines after the item at address ``ea``.'''
        res = cls.get_suffix, cls.set_suffix, cls.del_suffix
        return cls.__insert_space(ea, count, res)
    @utils.multicase(ea=six.integer_types, count=six.integer_types)
    @classmethod
    def postappend(cls, ea, count):
        '''Append ``count`` lines after the item at address ``ea``.'''
        res = cls.get_suffix, cls.set_suffix, cls.del_suffix
        return cls.__append_space(ea, count, res)

    @utils.multicase(count=six.integer_types)
    @classmethod
    def preinsert(cls, count):
        '''Insert ``count`` lines in front of the item at the current address.'''
        return cls.preinsert(ui.current.address(), count)
    @utils.multicase(count=six.integer_types)
    @classmethod
    def preappend(cls, count):
        '''Append ``count`` lines in front of the item at the current address.'''
        return cls.preappend(ui.current.address(), count)

    @utils.multicase(count=six.integer_types)
    @classmethod
    def postinsert(cls, count):
        '''Insert ``count`` lines after the item at the current address.'''
        return cls.postinsert(ui.current.address(), count)
    @utils.multicase(count=six.integer_types)
    @classmethod
    def postappend(cls, count):
        '''Append ``count`` lines after the item at the current address.'''
        return cls.postappend(ui.current.address(), count)

    insert, append = utils.alias(preinsert, 'extra'), utils.alias(preappend, 'extra')
ex = extra  # XXX: ns alias

class set(object):
    """
    Namespace for setting the type of an address within the database. This
    allows one to apply a particular type to a given address. This allows
    one to specify whether a type is a string, undefined, code, data, an
    array, or even a structure.
    """
    @utils.multicase()
    @classmethod
    def unknown(cls):
        '''Set the data at the current address to undefined.'''
        return cls.unknown(ui.current.address())
    @utils.multicase(ea=six.integer_types)
    @classmethod
    def unknown(cls, ea):
        '''Set the data at address ``ea`` to undefined.'''
        cb = idaapi.get_item_size(ea)
        ok = idaapi.do_unknown_range(ea, cb, idaapi.DOUNK_SIMPLE)
        return cb
    @utils.multicase(ea=six.integer_types, size=six.integer_types)
    @classmethod
    def unknown(cls, ea, size):
        '''Set the data at address ``ea`` to undefined.'''
        cb = idaapi.get_item_size(ea)
        ok = idaapi.do_unknown_range(ea, size, idaapi.DOUNK_SIMPLE)
        # FIXME: check the result, and return the calculated size
        return size
    undef = undefine = undefined = utils.alias(unknown, 'set')

    @utils.multicase()
    @classmethod
    def code(cls):
        '''Set the data at the current address to code.'''
        return cls.code(ui.current.address())
    @utils.multicase(ea=six.integer_types)
    @classmethod
    def code(cls, ea):
        '''Set the data at address ``ea`` to code.'''
        return idaapi.create_insn(ea)

    @utils.multicase(size=six.integer_types)
    @classmethod
    def data(cls, size, **type):
        '''Set the data at the current address to have the specified ``size`` and ``type``.'''
        return cls.data(ui.current.address(), size, **type)
    @utils.multicase(ea=six.integer_types, size=six.integer_types)
    @classmethod
    def data(cls, ea, size, **type):
        """Set the data at address ``ea`` to have the specified ``size`` and ``type``.

        If ``type`` is not specified, then choose the correct type based on the size.
        """
        lookup = {
            1 : idaapi.FF_BYTE, 2 : idaapi.FF_WORD, 4 : idaapi.FF_DWRD,
            8 : idaapi.FF_QWRD
        }

        # Older versions of IDA might not define FF_OWRD, so we just
        # try and add if its available. We fall back to an array anyways.
        if hasattr(idaapi, 'FF_OWRD'): lookup[16] = idaapi.FF_OWRD

        res = type['type'] if 'type' in type else lookup[size]
        if idaapi.__version__ < 7.0:
            ok = idaapi.do_data_ex(ea, idaapi.FF_STRU if isinstance(res, _structure.structure_t) else res, size, res.id if isinstance(res, _structure.structure_t) else 0)
        elif isinstance(res, _structure.structure_t):
            ok = idaapi.create_struct(ea, size, res.id)
        elif res == idaapi.FF_ALIGN and hasattr(idaapi, 'create_align'):
            ok = idaapi.create_align(ea, size, 0)
        else:
            ok = idaapi.create_data(ea, res, size, 0)
        return idaapi.get_item_size(ea) if ok else 0

    @utils.multicase()
    @classmethod
    def alignment(cls, **alignment):
        '''Set the data at the current address as aligned with the specified ``alignment``.'''
        return cls.align(ui.current.address(), **alignment)
    @utils.multicase(ea=six.integer_types)
    @classmethod
    def alignment(cls, ea, **alignment):
        """Set the data at address ``ea`` as aligned.

        If ``alignment`` is specified, then use it as the default alignment.
        If ``size`` is specified, then align that number of bytes.
        """
        if not type.is_unknown(ea):
            raise TypeError("{:s}.set.align({:#x}, ...) : Data at specified address has already been defined.".format('.'.join((__name__, cls.__name__)), ea))

        # grab the size out of the kwarg
        if 'size' in alignment:
            size = alignment['size']

        # otherwise, figure it out by counting repetitions
        # if the address is actually initialized
        elif type.is_initialized(ea):
            size, by = 0, read(ea, 1)
            while read(ea + size, 1) == by:
                size += 1
            pass

        # if it's uninitialized, then use the nextlabel as the
        # boundary to determine the size
        else:
            size = address.nextlabel(ea) - ea

        # if idaapi.create_align doesn't exist, then just hand this
        # off to idaapi.create_data with the determined size.
        if not hasattr(idaapi, 'create_align'):
            return cls.data(ea, size, type=idaapi.FF_ALIGN)

        # grab the aligment out of the kwarg
        if any(k in alignment for k in ('align', 'alignment')):
            align = builtins.next((alignment[k] for k in ('align', 'alignment') if k in alignment))
            e = math.trunc(math.log(align) / math.log(2))

        # or we again...just figure it out via brute force
        else:
            e, target = 13, ea + size
            while e > 0:
                if target & (2**e-1) == 0:
                    break
                e -= 1

        # we should be good to go
        ok = idaapi.create_align(ea, size, e)

        # return the new size, or a failure
        return idaapi.get_item_size(ea) if ok else 0
    align = aligned = utils.alias(alignment, 'set')

    @utils.multicase()
    @classmethod
    def string(cls, **type):
        '''Set the data at the current address to a string with the specified ``type``.'''
        return cls.string(ui.current.address(), **type)
    @utils.multicase(ea=six.integer_types)
    @classmethod
    def string(cls, ea, **type):
        '''Set the data at address ``ea`` to a string with the specified ``type``.'''
        type = type.get('type', idaapi.ASCSTR_LAST)
        ok = idaapi.make_ascii_string(ea, 0, type)
        return idaapi.get_item_size(ea) if ok else 0
    @utils.multicase(ea=six.integer_types, size=six.integer_types)
    @classmethod
    def string(cls, ea, size, **type):
        """Set the data at address ``ea`` to a string with the specified ``size``.

        If ``type`` is specified, use a string of the specified type.
        """
        type = type.get('type', idaapi.ASCSTR_LAST)
        ok = idaapi.make_ascii_string(ea, size, type)
        return idaapi.get_item_size(ea) if ok else 0

    class integer(object):
        """
        Namespace used for applying various sized integer types to a particular
        address.

        This namespace is also aliased as `database.set.i`.
        """
        @utils.multicase()
        @classmethod
        def byte(cls):
            '''Set the data at the current address to a byte.'''
            return cls.byte(ui.current.address())
        @utils.multicase(ea=six.integer_types)
        @classmethod
        def byte(cls, ea):
            '''Set the data at address ``ea`` to a byte.'''
            return set.data(ea, 1, type=idaapi.FF_BYTE)

        @utils.multicase()
        @classmethod
        def word(cls):
            '''Set the data at the current address to a word.'''
            return cls.word(ui.current.address())
        @utils.multicase(ea=six.integer_types)
        @classmethod
        def word(cls, ea):
            '''Set the data at address ``ea`` to a word.'''
            return set.data(ea, 2, type=idaapi.FF_WORD)

        @utils.multicase()
        @classmethod
        def dword(cls):
            '''Set the data at the current address to a double-word.'''
            return cls.dword(ui.current.address())
        @utils.multicase(ea=six.integer_types)
        @classmethod
        def dword(cls, ea):
            '''Set the data at address ``ea`` to a double-word.'''
            return set.data(ea, 4, type=idaapi.FF_DWRD)

        @utils.multicase()
        @classmethod
        def qword(cls):
            '''Set the data at the current address to a quad-word.'''
            return cls.qword(ui.current.address())
        @utils.multicase(ea=six.integer_types)
        @classmethod
        def qword(cls, ea):
            '''Set the data at address ``ea`` to a quad-word.'''
            return set.data(ea, 8, type=idaapi.FF_QWRD)

        @utils.multicase()
        @classmethod
        def oword(cls):
            '''Set the data at the current address to an octal-word.'''
            return cls.owrd(ui.current.address())
        @utils.multicase(ea=six.integer_types)
        @classmethod
        def oword(cls, ea):
            '''Set the data at address ``ea`` to an octal-word.'''
            return set.data(ea, 16, type=idaapi.FF_OWRD)
    i = integer # XXX: ns alias

    @utils.multicase(type=_structure.structure_t)
    @classmethod
    def structure(cls, type):
        '''Set the data at the current address to the structure_t specified by ``type``.'''
        return cls.structure(ui.current.address(), type)
    @utils.multicase(ea=six.integer_types, type=_structure.structure_t)
    @classmethod
    def structure(cls, ea, type):
        '''Set the data at address ``ea`` to the structure_t specified by ``type``.'''
        return cls.data(ea, type.size, type=type)
    struc = struct = utils.alias(structure, 'set')

    # FIXME: implement these with either pythonic types, or array.array
    @utils.multicase(length=six.integer_types)
    @classmethod
    def array(cls, type, length):
        '''Unimplemented.'''
        raise NotImplementedError
    @utils.multicase(ea=six.integer_types, length=six.integer_types)
    @classmethod
    def array(cls, ea, type, length):
        '''Unimplemented.'''
        raise NotImplementedError

class get(object):
    """
    Namespace used to fetch data from the database at a given address. This
    allows one to interpret the meaning that has been defined and then act
    on it. These include standard function for reading integers of different
    sizes, structures, and even arrays.
    """
    @utils.multicase()
    @classmethod
    def unsigned(cls, **byteorder):
        '''Read an unsigned integer from the current address.'''
        ea = ui.current.address()
        return cls.unsigned(ea, type.size(ea), **byteorder)
    @utils.multicase(size=six.integer_types)
    @classmethod
    def unsigned(cls, ea, **byteorder):
        '''Read an unsigned integer from the address ``ea`` using the size defined in the database.'''
        return cls.unsigned(ea, type.size(ea), **byteorder)
    @utils.multicase(ea=six.integer_types, size=six.integer_types)
    @classmethod
    def unsigned(cls, ea, size, **byteorder):
        """Read an unsigned integer from the address ``ea`` with the specified ``size``.

        If ``byteorder`` is 'big' then read in big-endian form.
        If ``byteorder`` is 'little' then read in little-endian form.

        The default value of ``byteorder`` is the same as specified by the database architecture.
        """
        data = read(ea, size)
        endian = byteorder.get('order', None) or byteorder.get('byteorder', config.byteorder())
        if endian.lower().startswith('little'):
            data = data[::-1]
        return reduce(lambda x,y: x << 8 | six.byte2int(y), data, 0)

    @utils.multicase()
    @classmethod
    def signed(cls, **byteorder):
        '''Read a signed integer from the current address.'''
        ea = ui.current.address()
        return cls.signed(ea, type.size(ea), **byteorder)
    @utils.multicase(size=six.integer_types)
    @classmethod
    def signed(cls, ea, **byteorder):
        '''Read a signed integer from the address ``ea`` using the size defined in the database.'''
        return cls.signed(ea, type.size(ea), **byteorder)
    @utils.multicase(ea=six.integer_types, size=six.integer_types)
    @classmethod
    def signed(cls, ea, size, **byteorder):
        """Read a signed integer from the address ``ea`` with the specified ``size``.

        If ``byteorder`` is 'big' then read in big-endian form.
        If ``byteorder`` is 'little' then read in little-endian form.

        The default value of ``byteorder`` is the same as specified by the database architecture.
        """
        bits = size*8
        sf = (2**bits)>>1
        res = cls.unsigned(ea, size, **byteorder)
        return (res - (2**bits)) if res&sf else res

    class integer(object):
        """
        Namespace containing the different ISO standard integer types that
        can be used to read integers out of the database.

        This namespace is also aliased as `database.get.i`.
        """
        @utils.multicase()
        def __new__(cls, **byteorder):
            return get.unsigned(**byteorder)
        @utils.multicase(ea=six.integer_types)
        def __new__(cls, ea, **byteorder):
            return get.unsigned(ea, **byteorder)
        @utils.multicase(ea=six.integer_types, size=six.integer_types)
        def __new__(cls, ea, size, **byteorder):
            return get.unsigned(ea, size, **byteorder)

        @utils.multicase()
        @classmethod
        def uint8_t(cls, **byteorder):
            '''Read a `uint8_t` from the current address.'''
            return get.unsigned(ui.current.address(), 1, **byteorder)
        @utils.multicase(ea=six.integer_types)
        @classmethod
        def uint8_t(cls, ea, **byteorder):
            '''Read a `uint8_t` from the address ``ea``.'''
            return get.unsigned(ea, 1, **byteorder)
        @utils.multicase()
        @classmethod
        def sint8_t(cls, **byteorder):
            '''Read a `sint8_t` from the current address.'''
            return get.signed(ui.current.address(), 1, **byteorder)
        @utils.multicase(ea=six.integer_types)
        @classmethod
        def sint8_t(cls, ea, **byteorder):
            '''Read a `sint8_t` from the address ``ea``.'''
            return get.signed(ea, 1, **byteorder)
        ubyte1, sbyte1 = utils.alias(uint8_t, 'get.integer'), utils.alias(sint8_t, 'get.integer')

        @utils.multicase()
        @classmethod
        def uint16_t(cls, **byteorder):
            '''Read a `uint16_t` from the current address.'''
            return get.unsigned(ui.current.address(), 2, **byteorder)
        @utils.multicase(ea=six.integer_types)
        @classmethod
        def uint16_t(cls, ea, **byteorder):
            '''Read a `uint16_t` from the address ``ea``.'''
            return get.unsigned(ea, 2, **byteorder)
        @utils.multicase()
        @classmethod
        def sint16_t(cls, **byteorder):
            '''Read a `sint16_t` from the current address.'''
            return get.signed(ui.current.address(), 2, **byteorder)
        @utils.multicase(ea=six.integer_types)
        @classmethod
        def sint16_t(cls, ea, **byteorder):
            '''Read a `sint16_t` from the address ``ea``.'''
            return get.signed(ea, 2, **byteorder)
        uint2, sint2 = utils.alias(uint16_t, 'get.integer'), utils.alias(sint16_t, 'get.integer')

        @utils.multicase()
        @classmethod
        def uint32_t(cls, **byteorder):
            '''Read a `uint32_t` from the current address.'''
            return get.unsigned(ui.current.address(), 4, **byteorder)
        @utils.multicase(ea=six.integer_types)
        @classmethod
        def uint32_t(cls, ea, **byteorder):
            '''Read a `uint32_t` from the address ``ea``.'''
            return get.unsigned(ea, 4, **byteorder)
        @utils.multicase()
        @classmethod
        def sint32_t(cls, **byteorder):
            '''Read a `sint32_t` from the current address.'''
            return get.signed(ui.current.address(), 4, **byteorder)
        @utils.multicase(ea=six.integer_types)
        @classmethod
        def sint32_t(cls, ea, **byteorder):
            '''Read a `sint32_t` from the address ``ea``.'''
            return get.signed(ea, 4, **byteorder)
        uint4, sint4 = utils.alias(uint32_t, 'get.integer'), utils.alias(sint32_t, 'get.integer')

        @utils.multicase()
        @classmethod
        def uint64_t(cls, **byteorder):
            '''Read a `uint64_t` from the current address.'''
            return get.unsigned(ui.current.address(), 8, **byteorder)
        @utils.multicase(ea=six.integer_types)
        @classmethod
        def uint64_t(cls, ea, **byteorder):
            '''Read a `uint64_t` from the address ``ea``.'''
            return get.unsigned(ea, 8, **byteorder)
        @utils.multicase()
        @classmethod
        def sint64_t(cls, **byteorder):
            '''Read a `sint64_t` from the current address.'''
            return get.signed(ui.current.address(), 8, **byteorder)
        @utils.multicase(ea=six.integer_types)
        @classmethod
        def sint64_t(cls, ea, **byteorder):
            '''Read a `sint64_t` from the address ``ea``.'''
            return get.signed(ea, 8, **byteorder)
        uint8, sint8 = utils.alias(uint64_t, 'get.integer'), utils.alias(sint64_t, 'get.integer')

        @utils.multicase()
        @classmethod
        def uint128_t(cls, **byteorder):
            '''Read a `uint128_t` from the current address.'''
            return get.unsigned(ui.current.address(), 16)
        @utils.multicase(ea=six.integer_types)
        @classmethod
        def uint128_t(cls, ea, **byteorder):
            '''Read a `uint128_t` from the address ``ea``.'''
            return get.unsigned(ea, 16, **byteorder)
        @utils.multicase()
        @classmethod
        def sint128_t(cls, **byteorder):
            '''Read a `sint128_t` from the current address.'''
            return get.signed(ui.current.address(), 16)
        @utils.multicase(ea=six.integer_types)
        @classmethod
        def sint128_t(cls, ea, **byteorder):
            '''Read a `sint128_t` from the address ``ea``.'''
            return get.signed(ea, 16, **byteorder)

    i = integer # XXX: ns alias

    @utils.multicase()
    @classmethod
    def array(cls, **length):
        '''Return the values of the array at the current address.'''
        return cls.array(ui.current.address(), **length)
    @utils.multicase(ea=six.integer_types)
    @classmethod
    def array(cls, ea, **length):
        """Return the values of the array at the address specified by ``ea``.

        If the int ``length`` is defined, then use it as the number of elements for the array.
        """
        ea = interface.address.within(ea)
        numerics = {
            idaapi.FF_BYTE : 'B',
            idaapi.FF_WORD : 'H',
            idaapi.FF_DWRD : 'L',
            idaapi.FF_FLOAT : 'f',
            idaapi.FF_DOUBLE : 'd',
        }

        # Some 32-bit versions of python might not have array.array('Q')
        # and some versions of IDA also might not have FF_QWRD..
        try:
            array.array('Q')
            numerics[idaapi.FF_QWRD] = 'Q'
        except (AttributeError,ValueError):
            pass

        lnumerics = {
            idaapi.FF_QWRD : 8,
        }

        # FF_OWORD, FF_YWORD and FF_ZWORD might not exist in older versions
        # of IDA, so try to add them to lnumerics "softly".
        try:
            lnumerics[idaapi.FF_OWORD] = 16,
            lnumerics[idaapi.FF_YWORD] = 32
            lnumerics[idaapi.FF_ZWORD] = 64
        except AttributeError:
            pass

        strings = {
            1 : 'c',
            2 : 'u',
        }
        F, T = type.flags(ea), type.flags(ea, idaapi.DT_TYPE)
        if T == idaapi.FF_ASCI:
            elesize = idaapi.get_full_data_elsize(ea, F)
            t = strings[elesize]
        elif T == idaapi.FF_STRU:
            t, total = type.structure.id(ea), idaapi.get_item_size(ea)
            cb = _structure.size(t)
            # FIXME: this math doesn't work (of course) with dynamically sized structures
            count = length.get('length', math.trunc(math.ceil(float(total) / cb)))
            return [ cls.structure(ea + i*cb, id=t) for i in six.moves.range(count) ]
        elif T in numerics:
            ch = numerics[T]
            # FIXME: return signed version of number
            t = ch.lower() if F & idaapi.FF_SIGN == idaapi.FF_SIGN else ch
        elif T in lnumerics:
            cb, total = lnumerics[T], idaapi.get_item_size(ea)
            # FIXME: return signed version of number
            t = get.signed if F & idaapi.FF_SIGN == idaapi.FF_SIGN else get.unsigned
            count = length.get('length', math.trunc(math.ceil(float(total) / cb)))
            return [ t(ea + i*cb, cb) for i in six.moves.range(count) ]
        else:
            query_l = itertools.imap(utils.unbox('{:s}={!r}'.format), six.iteritems(length))
            raise TypeError("{:s}.array({:#x}{:s}) : Unknown DT_TYPE found in flags at address {:#x}. : {:#x} & idaapi.DT_TYPE = {:#x}".format('.'.join((__name__, cls.__name__)), ea, (', '+', '.join(query_l)) if query_l else '', ea, F, T))

        total, cb = type.array.size(ea), type.array.element(ea)
        count = length.get('length', type.array.length(ea))
        res = array.array(t, read(ea, count * cb))
        if len(res) != count:
            logging.warn("{:s}.get({:#x}) : Unexpected length : ({:d} != {:d})".format('.'.join((__name__, cls.__name__)), ea, len(res), count))
        return res

    @utils.multicase()
    @classmethod
    def structure(cls):
        return cls.structure(ui.current.address())
    @utils.multicase(ea=six.integer_types)
    @classmethod
    def structure(cls, ea, **structure):
        """Return the `structure_t` at address ``ea`` as a dict of ctypes.

        If the ``structure`` argument is specified, then use that specific structure type.
        """
        ea = interface.address.within(ea)

        key = builtins.next((k for k in ('structure', 'struct', 'struc', 'sid', 'id') if k in structure), None)
        if key is None:
            sid = type.structure.id(ea)
        else:
            res = structure.get(key, None)
            sid = res.id if isinstance(res, _structure.structure_t) else res

        # FIXME: add support for string types
        # FIXME: consolidate this conversion into interface or something
        st = _structure.instance(sid, offset=ea)
        typelookup = {
            (int,-1) : ctypes.c_int8, (int,1) : ctypes.c_uint8,
            (int,-2) : ctypes.c_int16, (int,2) : ctypes.c_uint16,
            (int,-4) : ctypes.c_int32, (int,4) : ctypes.c_uint32,
            (int,-8) : ctypes.c_int64, (int,8) : ctypes.c_uint64,
            (float,4) : ctypes.c_float, (float,8) : ctypes.c_double,
        }

        res = {}
        for m in st.members:
            t, val = m.type, read(m.offset, m.size) or ''
            try:
                ct = typelookup[t]
            except KeyError:
                ty, sz = t if isinstance(t, builtins.tuple) else (m.type, 0)
                if isinstance(t, builtins.list):
                    t = typelookup[tuple(ty)]
                    ct = t*sz
                elif ty in {chr, str}:
                    ct = ctypes.c_char*sz
                else:
                    ct = None
            finally:
                res[m.name] = val if any(_ is None for _ in (ct, val)) else ctypes.cast(ctypes.pointer(ctypes.c_buffer(val)), ctypes.POINTER(ct)).contents
        return res
    struc = struct = utils.alias(structure, 'get')

    class switch(object):
        """
        Function for fetching an instance of a `switch_t` from a given address.
        Despite this being a namespace, by default it is intended to be used
        as a function against any known component of a switch. It will then
        return a class that allows one to query the different attributes of
        an `idaapi.switch_info_t`.
        """
        @classmethod
        def __getlabel(cls, ea):
            f = type.flags(ea)
            if idaapi.has_dummy_name(f) or idaapi.has_user_name(f):
                drefs = (ea for ea in xref.data_up(ea))
                refs = (ea for ea in itertools.chain(*itertools.imap(xref.up, drefs)) if idaapi.get_switch_info_ex(ea) is not None)
                try:
                    ea = builtins.next(refs)
                    res = idaapi.get_switch_info_ex(ea)
                    return interface.switch_t(res)
                except StopIteration:
                    pass
            raise TypeError("{:s}({:#x}) : Unable to instantiate a switch_info_ex_t at target label.".format('.'.join((__name__, 'type', cls.__name__)), ea))

        @classmethod
        def __getarray(cls, ea):
            refs = (ea for ea in xref.up(ea) if idaapi.get_switch_info_ex(ea) is not None)
            try:
                ea = builtins.next(refs)
                res = idaapi.get_switch_info_ex(ea)
                return interface.switch_t(res)
            except StopIteration:
                pass
            raise TypeError("{:s}({:#x}) : Unable to instantiate a switch_info_ex_t at switch array.".format('.'.join((__name__, 'type', cls.__name__)), ea))

        @classmethod
        def __getinsn(cls, ea):
            res = idaapi.get_switch_info_ex(ea)
            if res is None:
                raise TypeError("{:s}({:#x}) : Unable to instantiate a switch_info_ex_t at branch instruction.".format('.'.join((__name__, 'type', cls.__name__)), ea))
            return interface.switch_t(res)

        @utils.multicase()
        def __new__(cls):
            '''Return the switch at the current address.'''
            return cls(ui.current.address())
        @utils.multicase(ea=six.integer_types)
        def __new__(cls, ea):
            '''Return the switch at the address ``ea``.'''
            ea = interface.address.within(ea)
            try: return cls.__getinsn(ea)
            except TypeError: pass
            try: return cls.__getarray(ea)
            except TypeError: pass
            try: return cls.__getlabel(ea)
            except TypeError: pass
            raise TypeError("{:s}({:#x}) : Unable to instantiate a switch_info_ex_t.".format('.'.join((__name__, 'type', cls.__name__)), ea))

