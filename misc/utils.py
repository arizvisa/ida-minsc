"""
Utilities module (internal)

This module contains a number of tools that help with the interface for this
plugin. This contains things such as the multicase decorator, the matcher
class for querying and filtering lists of things, support for aliasing
functions, and a number of functional programming primitives (combinators).
"""

import six, builtins

import os, logging, weakref
import functools, operator, itertools
import sys, codecs, heapq, collections, array, math
logging = logging.getLogger(__name__)

import internal, internal.types
import idaapi, ida, ctypes

__all__ = [
    'fpack', 'funpack', 'fcar', 'fcdr',
    'finstance', 'fhasitem', 'fgetitem', 'fitem', 'fsetitem', 'fdelitem', 'fhasattr', 'fgetattr', 'fattribute', 'fsetattr', 'fsetattribute',
    'fconstant', 'fidentity', 'fdefault', 'fcompose', 'fdiscard', 'fcondition', 'fthrough',
    'flazy', 'fpartial', 'fapply', 'fapplyto', 'frpartial', 'freverse',
    'fthrow', 'fcatch',
    'fcomplement', 'fnot',
    'ilist', 'liter', 'ituple', 'titer',
    'icount', 'itake', 'iget', 'nth', 'first', 'second', 'third', 'last',
    'iterslice', 'itermap', 'iterfilter', 'iterzip', 'iterchain',
    'listslice', 'listmap', 'listfilter', 'listzip',
    'islice', 'imap', 'ifilter', 'ichain', 'izip',
    'lslice', 'lmap', 'lfilter', 'lzip',
    'flatmap'
]

### functional programming combinators (FIXME: probably better to document these with examples)

# return a closure that executes `F` with the arguments boxed and concatenated.
fpack = lambda F, *a, **k: lambda *ap, **kp: F(a + ap, **{ key : value for key, value in itertools.chain(k.items(), kp.items()) })
# return a closure that executes `F` with all of its arguments concatenated and unboxed.
funpack = lambda F, *a, **k: lambda *ap, **kp: F(*(a + functools.reduce(operator.add, builtins.map(builtins.tuple, ap), ())), **{ key : value for key, value in itertools.chain(k.items(), kp.items()) })
# return a closure that executes `F` with only its first argument.
fcar = lambda F, *a, **k: lambda *ap, **kp: F(*(a + ap[:1]), **{ key : value for key, value in itertools.chain(k.items(), kp.items()) })
# return a closure that executes `F` with all of it arguments but the first.
fcdr = lambda F, *a, **k: lambda *ap, **kp: F(*(a + ap[1:]), **{ key : value for key, value in itertools.chain(k.items(), kp.items()) })
# return a closure that will check that `object` is an instance of `type`.
finstance = lambda *type: lambda object: builtins.isinstance(object, type)
# return a closure that will check if `object` has an item `key`.
fhasitem = lambda key: lambda object: operator.contains(object, key)
# return a closure that will get a particular element from an object.
fgetitem = fitem = lambda item, *default: lambda object: default[0] if default and item not in object else object[item]
# return a closure that will set a particular element on an object.
fsetitem = lambda item: lambda value: lambda object: operator.setitem(object, item, value) or object
# return a closure that will remove a particular element from an object and return the modified object
fdelitem = lambda *items: fcompose(fthrough(fidentity, *[fcondition(fhasitem(item))(frpartial(operator.delitem, item), None) for item in items]), builtins.iter, builtins.next)
# return a closure that will check if `object` has an `attribute`.
fhasattr = lambda attribute: lambda object: builtins.hasattr(object, attribute)
# return a closure that will get a particular attribute from an object.
fgetattr = fattribute = lambda attribute, *default: lambda object: getattr(object, attribute, *default)
# return a closure that will set a particular attribute on an object.
fsetattr = fsetattribute = lambda attribute: lambda value: lambda object: builtins.setattr(object, attribute, value) or object
# return a closure that always returns `object`.
fconstant = lambda object: lambda *a, **k: object
# a closure that returns its argument always.
fidentity = lambda object: object
# a closure that returns a default value if its object is false-y
fdefault = lambda default: lambda object: object or default
# return a closure that executes a list of functions one after another from left-to-right.
fcompose = lambda *Fa: functools.reduce(lambda F1, F2: lambda *a: F1(F2(*a)), builtins.reversed(Fa))
# return a closure that executes function `F` whilst discarding any arguments passed to it.
fdiscard = lambda F, *a, **k: lambda *ap, **kp: F(*a, **k)
# return a closure using the functions in `critiques` with its parameters to return the result of the matching `truths` if any are successful or the last `truths` if not.
fcondition = lambda *critiques: lambda *truths: \
    (lambda false, critiques_and_truths=[pair for pair in zip(critiques, ((t if builtins.callable(t) else fconstant(t)) for t in truths))]: \
        lambda *a, **k: next((true for crit, true in critiques_and_truths if crit(*a, **k)), false if builtins.callable(false) else fconstant(false))(*a, **k) \
    )(false=truths[len(critiques)])
# return a closure that takes a list of functions to execute with the provided arguments
fthrough = fmap = lambda *Fa: lambda *a, **k: builtins.tuple(F(*a, **k) for F in Fa)
#lazy = lambda F, state={}: lambda *a, **k: state[(F, a, builtins.tuple(builtins.sorted(k.items())))] if (F, a, builtins.tuple(builtins.sorted(k.items()))) in state else state.setdefault((F, a, builtins.tuple(builtins.sorted(k.items()))), F(*a, **k))
#lazy = lambda F, *a, **k: lambda *ap, **kp: F(*(a + ap), **{ key : value for key, value in itertools.chain(k.items(), kp.items())})
# return a memoized closure that's lazy and only executes when evaluated
def flazy(F, *a, **k):
    '''Return a closure that will call the function `F` with the arguments `a` and keywords `k` reusing the result from any previous invocations.'''
    state = {}
    def lazy(*ap, **kp):
        '''Calls the captured function, arguments, and keywords with the additional arguments `ap` and keywords `kp` reusing the preserved result from any previous invocations.'''
        A, K = a + ap, frozenset(builtins.tuple(k.items()) + builtins.tuple(kp.items()))
        return state[(A, K)] if (A, K) in state else state.setdefault((A, K), F(*A, **{ key : value for key, value in itertools.chain(k.items(), kp.items()) }))
    return lazy
# return a closure with the function's arglist partially applied
fpartial = functools.partial
# return a closure that applies the provided arguments to the function `F`.
fapply = lambda F, *a, **k: lambda *ap, **kp: F(*(a + ap), **{ key : value for key, value in itertools.chain(k.items(), kp.items()) })
# return a closure that will use the specified arguments to call the provided function.
fapplyto = fcurry = lambda *a, **k: lambda F, *ap, **kp: F(*(a + ap), **{ key : value for key, value in itertools.chain(k.items(), kp.items()) })
# return a closure that applies the initial arglist to the end of function `F`.
frpartial = lambda F, *a, **k: lambda *ap, **kp: F(*(ap + builtins.tuple(builtins.reversed(a))), **{ key : value for key, value in itertools.chain(k.items(), kp.items()) })
# return a closure that applies the arglist to function `F` in reverse.
freverse = lambda F, *a, **k: lambda *ap, **kp: F(*builtins.reversed(a + ap), **{ key : value for key, value in itertools.chain(k.items(), kp.items()) })
# return a closure that raises exception `E` with the given arguments.
def fthrow(E, *a, **k):
    '''Return a closure that raises the exception `E` using the given arguments `a` and keywords `k`.'''
    def fraise(*ap, **kp):
        '''Raise the captured exception using the arguments `ap` and keywords `kp`.'''
        raise E(*(a + ap), **{key : value for key, value in itertools.chain(k.items(), kp.items())})
    return fraise
# return a closure that maps the given exceptions to a list of handlers which returns a closure that calls `F` with some arguments.
def fcatch(*exceptions, **map_exceptions):
    """Return a closure that calls the function `F` using the arguments `a` and keywords `k` capturing any exceptions that it raises.

    Usage:      fcatch(exceptions..., handler=exception)(traps..., handler=lambda *args, **keywords: result)(callable, ...)(*args, **keywords)
    Example:    fcatch(ValueError,    IDX=IndexError)   ('ValueError', IDX=lambda x1, x2: ('idx', x1, x2))  (callable, []) (x1, x2)
    """
    Fpartial, Fchain = functools.partial, itertools.chain
    def Fcallable(processors, F, *a, **k):
        '''Return a closure that calls the function `F` with the arguments `a` and keywords `k` while transforming any caught exceptions using `processors`.'''
        def handler(*ap, **kp):
            '''Executes the captured function with the arguments `ap` and keywords `kp` trapping any of the captured exceptions and transforming them to the captured handlers.'''
            try:
                return F(*Fchain(a, ap), **{key : value for key, value in Fchain(k.items(), kp.items())})
            except BaseException as E:
                cls, result, tb = sys.exc_info()
                processor = processors[cls] if cls in processors else processors[None] if None in processors else result
            return processor(*ap, **{key : value for key, value in kp.items()}) if callable(processor) else processor
        return handler
    def Fhandlers(*handlers, **map_handlers):
        '''Return a closure that will call a function trapping any captured exceptions with the given `handlers` and any matching exceptions with `map_handlers`.'''
        matches = {key for key in map_exceptions} & {key for key in map_handlers}
        processors = {exception : handler for exception, handler in Fchain(zip(exceptions, handlers + len(exceptions) * (None,)), [(map_exceptions[key], map_handlers[key]) for key in matches])}
        return Fpartial(Fcallable, processors)
    return Fhandlers
# boolean inversion of the result of a function
fcomplement = fnot = frpartial(fcompose, operator.not_)
# converts a list to an iterator, or an iterator to a list
ilist, liter = fcompose(builtins.iter, builtins.list), fcompose(builtins.list, builtins.iter)
# converts a tuple to an iterator, or an iterator to a tuple
ituple, titer = fcompose(builtins.iter, builtins.tuple), fcompose(builtins.tuple, builtins.iter)
# take `count` number of elements from an iterator
itake = lambda count: fcompose(builtins.iter, frpartial(itertools.islice, count), builtins.tuple)
# get the `nth` element from a thing.
iget = lambda count: fcompose(builtins.iter, frpartial(itertools.islice, count), builtins.tuple, operator.itemgetter(-1))
nth = lambda count: fcompose(builtins.iter, frpartial(itertools.islice, 1 + count), builtins.tuple, operator.itemgetter(-1))
# return the first, second, or third item of a thing.
first, second, third, last = nth(0), nth(1), nth(2), operator.itemgetter(-1)
# copy from itertools
iterslice, itermap, iterfilter, iterchain, iterzip = itertools.islice, getattr(itertools, 'imap', fcompose(builtins.map, builtins.iter)), getattr(itertools, 'ifilter', fcompose(builtins.filter, builtins.iter)), itertools.chain, getattr(itertools, 'izip', fcompose(builtins.zip, builtins.iter))
[islice, imap, ifilter, ichain, izip] = (iterslice, itermap, iterfilter, iterchain, iterzip)
# restoration of the Py2-compatible list types
listslice, listmap, listfilter, listzip = fcompose(itertools.islice, builtins.list), fcompose(builtins.map, builtins.list), fcompose(builtins.filter, builtins.list), fcompose(builtins.zip, builtins.list)
[lslice, lmap, lfilter, lzip] = (listmap, listmap, listfilter, listzip)
# count number of elements of a container
icount = count = fcompose(builtins.iter, builtins.list, builtins.len)
# map a function to any number of iterables and flatten its results
flatmap = lambda F, *iterables: itertools.chain(*imap(F, *iterables))

# cheap pattern-like matching
class Pattern(object):
    '''Base class for fake pattern matching against a tuple.'''
    def __eq__(self, other):
        return self.__cmp__(other) == 0
    __call__ = __eq__
    def __repr__(self):
        return 'Pattern()'
class PatternAny(Pattern):
    '''Object for matching against anything it is compared against.'''
    def __cmp__(self, other):
        return 0
    def __repr__(self):
        return "{:s}({:s})".format('Pattern', '*')
class PatternAnyType(Pattern):
    '''Object for matching against any type it is compared against.'''
    def __init__(self, *other):
        self.types = other
    def __cmp__(self, other):
        return 0 if isinstance(other, self.types) else -1
    def __types__(self):
        items = {item for item in []}
        for item in self.types:
            if isinstance(item, internal.types.unordered):
                for item in item:
                    items |= {item.__name__}
                continue
            items |= {item.__name__}
        return sorted(items)
    def __repr__(self):
        return "{:s}({:s})".format('Pattern', '|'.join(self.__types__()))

### compatibility namespace
class pycompat(object):
    """
    This namespace provides tools for interacting with some of the core
    callable types that are available from Python in a way that is compatible
    between all the supported versions. This allows one to interact with
    the names and attributes for a code or a function object in a generic way.
    """

    @classmethod
    def fullname(cls, object):
        '''Return the fully qualified name for the specified `object` as a string if possible.'''
        if isinstance(object, functools.partial):
            return "{:s}({:s}{:s}{:s})".format(cls.fullname(functools.partial), cls.fullname(object.func), ", {:s}".format(', '.join(map("{!s}".format, object.args))) if object.args else '', ", {:s}".format(string.kwargs(object.keywords)) if object.keywords else '')

        # Otherwise we'll have to just trust whatever name the object has.
        Fqualified_name = fattribute('__qualname__') if hasattr(object, '__qualname__') else cls.function.name if isinstance(object, internal.types.function) else cls.code.name if isinstance(object, internal.types.code) else fattribute('__name__', object.__name__)
        return '.'.join([object.__module__, Fqualified_name(object)] if hasattr(object, '__module__') else [Fqualified_name(object)])

    @classmethod
    def file(cls, callable):
        '''Return a tuple containing the filename and line number of the specified `callable`.'''
        func = callable.func if isinstance(callable, functools.partial) else cls.method.function(callable) if isinstance(callable, (staticmethod, classmethod, internal.types.method)) else callable

        if isinstance(func, internal.types.function):
            co = cls.function.code(func)
            filename, linenumber = cls.code.filename(co), cls.code.linenumber(co)

        # If it's not a function, then the best we can do is take a
        # huge performance hit and get the filename.
        else:
            module = cls.module(func)
            filename, linenumber = getattr(__import__(module), '__file__', '<builtin>'), -1
        res = os.path.relpath(filename, idaapi.get_user_idadir())
        return os.path.abspath(filename) if res.startswith(''.join(['..', os.path.sep])) else res, linenumber

    @classmethod
    def module(cls, object):
        '''Return the module name for the specified `object`.'''
        return getattr(object, '__module__', '')

    # this class definition gets used as a base class, before its name
    # gets reassigned later when it goes out of scope.
    class function(object):
        @classmethod
        def arguments(cls, function):
            '''Return a tuple containing the names of the arguments, keywords, and both variable argument types for the given `function`.'''
            c = pycompat.function.code(function)
            varnames_count, varnames_iter = pycompat.code.argcount(c), (item for item in pycompat.code.varnames(c))
            args = tuple(itertools.islice(varnames_iter, varnames_count))
            res = { a : v for v, a in zip(reversed(pycompat.function.defaults(function) or []), reversed(args)) }
            try: starargs = next(varnames_iter) if pycompat.code.flags(c) & pycompat.co_flags.CO_VARARGS else ""
            except StopIteration: starargs = ""
            try: kwdargs = next(varnames_iter) if pycompat.code.flags(c) & pycompat.co_flags.CO_VARKEYWORDS else ""
            except StopIteration: kwdargs = ""
            return args, res, (starargs, kwdargs)

        @classmethod
        def extract(cls, callable):
            '''Extract the function object from the given `callable` and return it.'''
            if isinstance(callable, internal.types.function):
                return callable
            elif isinstance(callable, internal.types.method):
                return pycompat.method.function(callable)
            elif isinstance(callable, internal.types.code):
                [res] = (item for item in gc.get_referrers(c) if pycompat.function.name(item) == pycompat.code.name(c) and isinstance(item, internal.types.function))
                return res
            elif isinstance(callable, internal.types.descriptor):
                return callable.__func__
            elif isinstance(callable, functools.partial):
                return callable.func
            raise internal.exceptions.InvalidTypeOrValueError(callable)

        @classmethod
        def constructor(cls, function):
            '''Return a closure that constructs the original callable for the type of the given `function`.'''
            if isinstance(function, internal.types.function):
                return lambda f: f
            elif isinstance(function, internal.types.method):
                self, method_t = pycompat.method.self(function), pycompat.method.type(function)
                return lambda f: pycompat.method.new(f, self, method_t)
            elif isinstance(function, internal.types.descriptor):
                descriptor_t = type(function)
                return lambda f: descriptor_t(f)
            elif sys.version_info.major < 3 and isinstance(function, internal.types.instance):
                instance_t = type(function)
                return lambda f: internal.types.InstanceType(instance_t, {key : value for key, value in f.__dict__.items()})
            elif isinstance(function, internal.types.class_t):
                type_t = type(item)
                return lambda f: type_t(item.__name__, item.__bases__, {key : value for key, value in f.__dict__.items()})
            elif isinstance(function, functools.partial):
                fpartial, args, keywords = functools.partial, function.args, function.keywords
                return lambda f: fpartial(f, *args, **keywords)
            raise internal.exceptions.InvalidTypeOrValueError(type(function))

    class function_2x(function):
        @classmethod
        def new(cls, code, globals, name, argdefs, closure):
            return internal.types.function(code, globals, name, argdefs, closure)

        @classmethod
        def name(cls, object):
            return object.func_name
        @classmethod
        def set_name(cls, object, name):
            result, object.func_name = object.func_name, name
            return result

        @classmethod
        def documentation(cls, object):
            return object.func_doc
        @classmethod
        def set_documentation(cls, object, string):
            result, object.func_doc = object.func_doc, string
            return result

        @classmethod
        def defaults(cls, object):
            return object.func_defaults
        @classmethod
        def globals(cls, object):
            return object.func_globals
        @classmethod
        def closure(cls, object):
            return object.func_closure
        @classmethod
        def code(cls, object):
            return object.func_code

    class function_3x(function_2x):
        @classmethod
        def name(cls, object):
            return object.__name__
        @classmethod
        def set_name(cls, object, name):
            result, object.__name__ = object.__name__, name
            return result

        @classmethod
        def documentation(cls, object):
            return object.__doc__
        @classmethod
        def set_documentation(cls, object, string):
            result, object.__doc__ = object.__doc__, string
            return result

        @classmethod
        def defaults(cls, object):
            return object.__defaults__
        @classmethod
        def globals(cls, object):
            return object.__globals__
        @classmethod
        def closure(cls, object):
            return object.__closure__
        @classmethod
        def code(cls, object):
            return object.__code__

    function = function_2x if sys.version_info.major < 3 else function_3x

    class code_2x(object):
        @classmethod
        def name(cls, object):
            return object.co_name
        @classmethod
        def flags(cls, object):
            return object.co_flags
        @classmethod
        def argcount(cls, object):
            return object.co_argcount
        @classmethod
        def varnames(cls, object):
            return object.co_varnames

        @classmethod
        def filename(cls, object):
            return object.co_filename
        @classmethod
        def linenumber(cls, object):
            return object.co_firstlineno

        cons = collections.namedtuple('code_t', ['co_argcount', 'co_nlocals', 'co_stacksize', 'co_flags', 'co_code', 'co_consts', 'co_names', 'co_varnames', 'co_filename', 'co_name', 'co_firstlineno', 'co_lnotab', 'co_freevars', 'co_cellvars'])
        @classmethod
        def unpack(cls, object):
            return cls.cons(*(getattr(object, item) for item in cls.cons._fields))
        @classmethod
        def unpack_extra(cls, object):
            return ()
        @classmethod
        def new(cls, attributes, extra=()):
            argcount, nlocals, stacksize, flags, code, consts, names, varnames, filename, name, firstlineno, lnotab, freevars, cellvars = attributes
            return internal.types.code(*attributes)

    class code_37(code_2x):
        @classmethod
        def unpack_extra(cls, object):
            return object.co_kwonlyargcount,
        @classmethod
        def new(cls, attributes, extra=(0,)):
            argcount, nlocals, stacksize, flags, code, consts, names, varnames, filename, name, firstlineno, lnotab, freevars, cellvars = attributes
            kwonlyargcount, = extra
            return internal.types.code(argcount, kwonlyargcount, nlocals, stacksize, flags, code, consts, names, varnames, filename, name, firstlineno, lnotab, freevars, cellvars)

    class code_38(code_2x):
        @classmethod
        def unpack_extra(cls, object):
            return object.co_posonlyargcount, object.co_kwonlyargcount
        @classmethod
        def new(cls, attributes, extra=(0, 0)):
            argcount, nlocals, stacksize, flags, code, consts, names, varnames, filename, name, firstlineno, lnotab, freevars, cellvars = attributes
            posonlyargcount, kwonlyargcount = extra
            return internal.types.code(argcount, posonlyargcount, kwonlyargcount, nlocals, stacksize, flags, code, consts, names, varnames, filename, name, firstlineno, lnotab, freevars, cellvars)

    class code_311(code_2x):
        @classmethod
        def unpack_extra(cls, object):
            return object.co_posonlyargcount, object.co_kwonlyargcount, object.co_qualname, object.co_exceptiontable
        @classmethod
        def new(cls, attributes, extra=(0, 0, str(), bytes())):
            argcount, nlocals, stacksize, flags, code, consts, names, varnames, filename, name, firstlineno, lnotab, freevars, cellvars = attributes
            posonlyargcount, kwonlyargcount, qualname, exceptiontable = extra
            return internal.types.code(argcount, posonlyargcount, kwonlyargcount, nlocals, stacksize, flags, code, consts, names, varnames, filename, name, qualname or name, firstlineno, lnotab, exceptiontable, freevars, cellvars)

    code = code_2x if sys.version_info.major < 3 else code_37 if (sys.version_info.major, sys.version_info.minor) < (3, 8) else code_38 if (sys.version_info.major, sys.version_info.minor) < (3, 11) else code_311

    class method(object):
        @classmethod
        def name(cls, object):
            self, plain, func = cls.self(object), object.__name__, object.__func__
            owner_t = self if isinstance(self, type) else self.__class__
            if not hasattr(object, '__qualname__'):
                return '.'.join([owner_t.__name__, plain])

            # if the qualified name didn't match, and our method name isn't in
            # the owner class, then the qualified name describes the super class
            # and we need to correct it.
            elif plain not in owner_t.__dict__:
                this = object.__qualname__.split('.')
                owner = owner_t.__qualname__.split('.')
                matching = [name for name, ownername in zip(this, owner) if name == ownername]
                iterable = itertools.chain(matching, [owner_t.__name__], this[-1:])
                return '.'.join(iterable)

            # if there's no difference between the owner and the qualified name,
            # then we can just trust the qualified name.
            elif getattr(object, '__qualname__', '').endswith('.'.join(['', owner_t.__name__, plain])):
                return object.__qualname__

            # otherwise use the qualified name of the class being derived from.
            return '.'.join([owner_t.__qualname__, plain])

    class method_2x(method):
        @classmethod
        def new(cls, function, instance, type):
            return internal.types.method(function, instance, type)

        @classmethod
        def self(cls, object):
            return object.im_self

        @classmethod
        def type(cls, object):
            return object.im_class

        @classmethod
        def function(cls, object):
            return object.im_func

    class method_3x(method):
        @classmethod
        def new(cls, function, instance, type=None):
            return internal.types.method(function, instance)

        @classmethod
        def self(cls, method):
            return method.__self__

        @classmethod
        def type(cls, method):
            self = method.__self__
            return self.__class__ if isinstance(self, object) else self

        @classmethod
        def function(cls, method):
            return method.__func__

    method = method_2x if sys.version_info.major < 3 else method_3x

    class co_flags_2x(object):
        CO_OPTIMIZED                = 0x00001
        CO_NEWLOCALS                = 0x00002
        CO_VARARGS                  = 0x00004
        CO_VARKEYWORDS              = 0x00008
        CO_NESTED                   = 0x00010
        CO_GENERATOR                = 0x00020
        CO_NOFREE                   = 0x00040

        CO_ITERABLE_COROUTINE       = 0x00100
        CO_GENERATOR_ALLOWED        = 0x01000
        CO_FUTURE_DIVISION          = 0x02000
        CO_FUTURE_ABSOLUTE_IMPORT   = 0x04000
        CO_FUTURE_WITH_STATEMENT    = 0x08000
        CO_FUTURE_PRINT_FUNCTION    = 0x10000
        CO_FUTURE_UNICODE_LITERALS  = 0x20000

    class co_flags_3x(co_flags_2x):
        CO_COROUTINE                = 0x00080
        CO_FUTURE_BARRY_AS_BDFL     = 0x40000
        CO_FUTURE_GENERATOR_STOP    = 0x80000

    class co_flags_311(co_flags_2x):
        CO_COROUTINE                = 0x0000080
        CO_ITERABLE_COROUTINE       = 0x0000100
        CO_ASYNC_GENERATOR          = 0x0000200

        CO_FUTURE_DIVISION          = 0x0020000
        CO_FUTURE_ABSOLUTE_IMPORT   = 0x0040000
        CO_FUTURE_WITH_STATEMENT    = 0x0080000
        CO_FUTURE_PRINT_FUNCTION    = 0x0100000
        CO_FUTURE_UNICODE_LITERALS  = 0x0200000

        CO_FUTURE_BARRY_AS_BDFL     = 0x0400000
        CO_FUTURE_GENERATOR_STOP    = 0x0800000
        CO_FUTURE_ANNOTATIONS       = 0x1000000

    co_flags = co_flags_2x if sys.version_info.major < 3 else co_flags_3x if sys.version_info.minor < 11 else co_flags_311

### decorators
class priority_tuple(object):
    """
    This class simulates a tuple because Python3's heapq implementation is
    fucking stupid and ignores the priority that we use in the tuple for
    sorting the values in the heapq.
    """
    def __init__(self, priority, items):
        self.priority, self.items = priority, items

    def __iter__(self):
        yield self.priority
        yield self.items

    def __cmp__(self, other):
        return cmp(self.priority, other.priority)
    def __lt__(self, other):
        return self.priority < other.priority
    def __gt__(self, other):
        return self.priority > other.priority

class multicase(object):
    """
    A lot of magic is in this class which allows one to define multiple cases
    for a single function.
    """
    cache_name = '__multicase_cache__'
    documentation_name = '__multicase_documentation__'

    def __new__(cls, *other, **t_args):
        '''Decorate a case of a function with the specified types.'''

        # Output some useful information to help the user if there's nothing that satisfies their parameters.
        def missing(packed_parameters, tree, table, documentation={}, ignored_parameter_count=0):
            '''Output the candidates for the callable that the user is attempting to use.'''
            args, kwds = packed_parameters
            Fcallable, Fhelp, Fprototype = "`{:s}`".format, "`help({:s})`".format, "{:s}".format

            # Basic configuration
            arrow, indent = ' -> ', 4

            # Some useful utilities for speaking english at our users.
            Fconjunction_or = lambda items: ', '.join(items[:-1]) + ", or {:s}".format(*items[-1:]) if len(items) > 1 else items[0]
            Fconjunction_and = lambda items: ', '.join(items[:-1]) + ", and {:s}".format(*items[-1:]) if len(items) > 1 else items[0]
            sorted_functions = [F for F in cls.sorted_documentation(documentation)]

            # Collect all parameter names, keywords, and documentation for describing what happened.
            description_arguments = [item.__class__.__name__ for item in args[ignored_parameter_count:]]
            description_keywords = ["{:s}={!s}".format(name, kwds[name].__class__.__name__) for name in kwds]

            iterable = ((F, documentation[F]) for F in sorted_functions)
            description_functions = {F : (prototype, F.__module__ if hasattr(F, '__module__') else None, fattribute('__qualname__', pycompat.code.name(pycompat.function.code(F)))(F)) for F, (prototype, _, _) in iterable}

            # Build the error message that is displayed as part of the exception.
            available_names = sorted({'.'.join([module, name]) if module else name for _, (_, module, name) in description_functions.items()})
            conjunctioned = Fconjunction_and([Fcallable(item) for item in available_names])
            description = Fconjunction_or(["{:s}({:s})".format(name, ', '.join(itertools.chain(description_arguments, description_keywords))) for name in available_names])
            message = u"{:s}: The given parameter type{:s} not match any of the available cases for the definition of {:s}.".format(description, ' does' if sum(map(len, [description_arguments, description_keywords])) == 1 else 's do', conjunctioned)

            # Build the list of candidates that the user will need to choose from.
            listing_message = "The functions that are available for {:s} are:".format(Fconjunction_and([Fhelp(item) for item in available_names]))
            iterable = ((F, description_functions[F]) for F in sorted_functions)
            prototypes = [(Fprototype('.'.join([module, item]) if module else item if module else item), documentation[F]) for F, (item, module, _) in iterable]

            # Calculate some lengths and use them to format our output in some meaningful way.
            maximum = max(len(prototype) for prototype, _ in prototypes) if prototypes else 0
            components = [(prototype, "{:s}{:s}".format(arrow, lines[0]) if len(lines) else '') for prototype, (_, lines, _) in prototypes]
            iterable = ("{: <{:d}s}{:s}".format(prototype, maximum, description) for prototype, description in components)
            listing = ["{: <{:d}s}{:s}".format('', indent, item) for item in iterable]

            # Now we have a message and a listing that we can just join together with a newline.
            raise internal.exceptions.UnknownPrototypeError('\n'.join(itertools.chain([message, '', listing_message], listing)))

        # These are just utility closures that can be attached to the entrypoint closure.
        def fetch_score(cache, *arguments, **keywords):
            '''Return a list of all the callables, their (transformed) parameters, and their score for the given `arguments` and `keywords`.'''
            tree, table = cache
            packed_parameters = arguments, keywords
            candidates = cls.match(packed_parameters, tree, table)
            scores = {F : cls.critique_and_transform(F, packed_parameters, tree, table) for F, _ in candidates}
            iterable = cls.preordered(packed_parameters, candidates, tree, table)
            ordered = ((F, scores[F]) for F, _ in iterable)
            return [(F, score, args, kwargs) for F, (args, kwargs, score) in ordered]

        def fetch_callable(cache, *arguments, **keywords):
            '''Return the first callable that matches the constraints for the given `arguments` and `keywords`.'''
            tree, table = cache
            packed_parameters = arguments, keywords
            candidates = cls.match(packed_parameters, tree, table)
            iterable = cls.preordered(packed_parameters, candidates, tree, table)
            packed = next(iterable)
            F, _ = packed
            return F

        def fetch_prototype(documentation, callable):
            '''Return the documentation prototype for the given `callable`.'''
            prototype, _, _ = documentation[callable]
            return prototype

        def fetch_candidates(cache, *arguments, **keywords):
            '''Return the unordered matches for the constraints specified by `arguments` and `keywords`.'''
            tree, table = cache
            packed_parameters = arguments, keywords
            return cls.match(packed_parameters, tree, table)

        def fetch_arguments(cache, *arguments, **keywords):
            '''Return the candidates for the constraints specified by `arguments`.'''
            tree, table = cache
            packed_parameters = arguments, keywords
            if keywords:
                logging.warning(u"{:s}({:s}{:s}{:s}): Discarding {:d} keyword{:s} due to {:s} being unused.".format('.'.join([__name__, cls.__name__, 'arguments']), ', '.join("{!r}".format(arg) if isinstance(arg, internal.types.string) else "{!s}".format(arg) for arg in arguments), ', ' if arguments and keywords else '', string.kwargs(keywords), len(keywords), *['', 'it'] if len(keywords) == 1 else ['s', 'them']))
            iterable = cls.filter_args(packed_parameters, tree, table)
            return [candidate for candidate in iterable]

        def fetch_keywords(cache, s_args, *arguments, **keywords):
            '''Return the candidates for the constraints specified by `keywords`.'''
            tree, table = cache
            packed_parameters = arguments, keywords
            if arguments:
                logging.warning(u"{:s}({:s}{:s}{:s}): Discarding {:d} argument{:s} due to {:s} being unused.".format('.'.join([__name__, cls.__name__, 'keywords']), ', '.join("{!r}".format(arg) if isinstance(arg, internal.types.string) else "{!s}".format(arg) for arg in arguments), ', ' if arguments and keywords else '', string.kwargs(keywords), len(arguments), *['', 'it'] if len(arguments) == 1 else ['s', 'them']))
            candidates = ((F, index) for F, (_, index, next) in tree[0].items() if index == next or index >= 0)
            iterable = cls.filter_keywords(candidates, packed_parameters, tree, table)
            return [candidate for candidate in iterable]

        def transform_parameters(cache, s_args, F, *arguments, **keywords):
            '''Return the transformed parameters for both `arguments` and `keywords` when calling the function `F`.'''
            tree, table = cache
            packed_parameters = tuple(itertools.chain(s_args * [object], arguments)), keywords
            if F not in tree[0]:
                raise RuntimeError("{:s}({:s}{:s}{:s}): An internal error occurred due to the requested function ({!s}) not being {:s} the defined case{:s}.".format('.'.join([__name__, cls.__name__, 'keywords']), ', '.join("{!r}".format(arg) if isinstance(arg, internal.types.string) else "{!s}".format(arg) for arg in arguments), ', ' if arguments and keywords else '', string.kwargs(keywords), F, *['a', ''] if len(tree[s_args]) == 1 else ['one of the', 's']))
            args, kwds, _ = cls.critique_and_transform(F, packed_parameters, tree, table)
            return args, kwds

        # This is the entry-point closure that gets used to update the actual wrapper with a new candidate.
        def result(wrapped):
            '''Return a function that will call the given `wrapped` function if the parameters meet the required type constraints.'''
            flattened_constraints = {argname : tuple(item for item in cls.flatten(types if isinstance(types, internal.types.unordered) else [types])) for argname, types in t_args.items()}

            # First we need to extract the function from whatever type it is
            # so that we can read any properties we need from it. We also extract
            # its "constructor" so that we can re-create it after we've processed it.
            try:
                cons, func = pycompat.function.constructor(wrapped), pycompat.function.extract(wrapped)
                if not callable(func):
                    raise internal.exceptions.InvalidTypeOrValueError

            except internal.exceptions.InvalidTypeOrValueError:
                logging.warning(u"{:s}(...): Refusing to create a case for a non-callable object ({!s}).".format('.'.join([__name__, cls.__name__]), wrapped))
                return wrapped

            # Next we need to extract all of the argument information from it. We also need to
            # determine whether it's a special type of some sort so that we know that its first
            # argument is irrelevant for our needs. With regards to this, we can't do anything
            # for methods since we see them before they get attached. However, we can explicitly
            # check if it's using the magic name "__new__" which uses an implicit parameter.
            args, defaults, (star, starstar) = pycompat.function.arguments(func)
            s_args = 1 if isinstance(wrapped, (internal.types.classmethod, internal.types.method)) or func.__name__ in {'__new__'} else 0

            # If the user decorated us whilst explicitly providing the previous
            # function that this case is a part of, then make sure that we use it.
            if len(other):
                ok, prev = True, other[0]

            # If we weren't given a function, then we need to be tricky and search
            # through our parent frame's locals. Hopefully it's using the same name.
            elif pycompat.function.name(func) in sys._getframe().f_back.f_locals:
                ok, prev = True, sys._getframe().f_back.f_locals[pycompat.function.name(func)]

            # Otherwise, we've hit first blood and this is the very first definition
            # of the function. This requires us to do some construction later.
            else:
                ok = False

            # So if we found an already-existing wrapper, then we need to steal its cache.
            res = ok and prev and pycompat.function.extract(prev)
            if ok and hasattr(res, cls.cache_name):
                owner, cache, documentation = res, getattr(res, cls.cache_name), getattr(res, cls.documentation_name)

            # Otherwise, we simply need to create a new cache entirely.
            else:
                owner, cache, documentation = func, ({}, {}), {}
                res = cls.new_wrapper(func, cache, Fmissing=functools.partial(missing, documentation=documentation, ignored_parameter_count=s_args))
                res.__module__ = getattr(wrapped, '__module__', getattr(func, '__module__', '__main__'))

                # Update our new wrapper with our cache (tree and table) and our
                # documentation state so that it not only works but it reads too.
                setattr(res, cls.cache_name, cache)
                setattr(res, cls.documentation_name, documentation)

                # Attach a few hardcoded utilities to the closure that we return. We add
                # some empty namespaces as the first argument if it's a classmethod or __new__.
                setattr(res, 'score', functools.partial(fetch_score, cache, *s_args * [object]))
                setattr(res, 'callable', functools.partial(fetch_callable, cache, *s_args * [object]))
                setattr(res, 'describe', functools.partial(fetch_prototype, documentation))

                # Assign some utilities that can be used for benchmarking certain components.
                setattr(res, 'candidates', functools.partial(fetch_candidates, cache, *s_args * [object]))
                setattr(res, 'arguments', functools.partial(fetch_arguments, cache, *s_args * [object]))
                setattr(res, 'keywords', functools.partial(fetch_keywords, cache, s_args))
                setattr(res, 'transform', functools.partial(transform_parameters, cache, s_args))

            # Now we need to add the function we extracted to our tree of candidate functions.
            constraints = {name : types for name, types in flattened_constraints.items()}
            tree, table = cache
            F = cls.add(func, constraints, tree, table)
            assert(F is func)

            # Verify that we constrained all of the available types. If any are left, then
            # we need to complain about it since we just added the case to our tree.
            if constraints:
                co = pycompat.function.code(func)
                description = '.'.join(getattr(func, attribute) for attribute in ['__module__', '__name__'] if hasattr(func, attribute))
                location = "{:s}:{:d}".format(pycompat.code.filename(co), pycompat.code.linenumber(co))
                error_constraints = {name : "{:s}={!s}".format(name, types.__name__ if isinstance(types, internal.types.type) or types in {internal.types.callable} else '|'.join(sorted(t_.__name__ for t_ in types)) if hasattr(types, '__iter__') else "{!r}".format(types)) for name, types in flattened_constraints.items()}
                logging.warning(u"@{:s}(...) : Unable to constrain {:d} parameter{:s} ({:s}) for prototype \"{:s}({:s})\" at {:s}.".format('.'.join([__name__, cls.__name__]), len(constraints), '' if len(constraints) == 1 else 's', ', '.join(constraints), description, ', '.join(error_constraints.get(name, name) for name in args[s_args:]), location))

            # Now we can use the information we collected about the function to
            # generate a documentation entry. Once we do this, then we completely
            # regenerate the documentation so that it's always up to date.
            documentation[func] = cls.render_documentation(func, flattened_constraints, args[:s_args])
            res.__doc__ = cls.document(documentation)

            # ..and then we can restore the original wrapper in all of its former glory.
            return cons(res)

        # Validate the types of all of our arguments and raise an exception if it used
        # an unsupported type.
        for name, types in t_args.items():
            if not isinstance(types, (internal.types.type, internal.types.tuple)) and types not in {internal.types.callable}:
                error_keywords = ("{:s}={!s}".format(name, types.__name__ if isinstance(types, internal.types.type) or types in {internal.types.callable} else '|'.join(t_.__name__ for t_ in types) if hasattr(types, '__iter__') else "{!r}".format(types)) for name, types in t_args.items())
                raise internal.exceptions.InvalidParameterError(u"@{:s}({:s}) : The value ({!s}) specified for parameter \"{:s}\" is not a supported type.".format('.'.join([__name__, cls.__name__]), ', '.join(error_keywords), types, string.escape(name, '"')))
            continue

        # Validate the types of our arguments that we were asked to decorate with, this
        # way we can ensure that our previously decorated functions are actually of the
        # correct type. We do this strictly to assist with debugging.
        try:
            [pycompat.function.extract(item) for item in other]
        except Exception:
            error_keywords = ("{:s}={!s}".format(name, types.__name__ if isinstance(types, internal.types.type) or types in {internal.types.callable} else '|'.join(item.__name__ for item in types) if hasattr(types, '__iter__') else "{!r}".format(types)) for name, types in t_args.items())
            raise internal.exceptions.InvalidParameterError(u"@{:s}({:s}) : The specified callable{:s} {!r} {:s} not of a valid type.".format('.'.join([__name__, cls.__name__]), ', '.join(error_keywords), '' if len(other) == 1 else 's', other, 'is' if len(other) == 1 else 'are'))

        # If we were given an unexpected number of arguments to decorate with, then
        # raise an exception. This is strictly done to assist with debugging.
        if len(other) > 1:
            error_keywords = ("{:s}={!s}".format(name, types.__name__ if isinstance(types, internal.types.type) or types in {internal.types.callable} else '|'.join(item.__name__ for item in types) if hasattr(types, '__iter__') else "{!r}".format(types)) for name, type in t_args.items())
            raise internal.exceptions.InvalidParameterError(u"@{:s}({:s}) : More than one callable ({:s}) was specified to add a case to. Refusing to add cases to more than one callable.".format('.'.join([__name__, cls.__name__]), ', '.join(error_keywords), ', '.join("\"{:s}\"".format(string.escape(pycompat.code.name(c) if isinstance(c, internal.types.code) else c.__name__, '"')) for c in other)))
        return result

    @classmethod
    def document(cls, descriptions):
        '''Generate the documentation for a multicased function using the given `descriptions`.'''
        result = []

        # Configure how we plan on joining each component of the documentation.
        arrow, indent = ' -> ', 4
        maximum = max(len(prototype) for F, (prototype, _, _) in descriptions.items()) if descriptions else 0

        # Collect each prototype and lines that compose each description.
        for F in cls.sorted_documentation(descriptions):
            prototype, lines, _ = descriptions[F]
            pointed = "{: <{:d}s}{:s}".format(prototype, maximum, arrow)
            iterable = (item for item in lines)
            result.append(''.join([pointed, next(iterable)]) if len(lines) else prototype)
            result.extend("{: >{padding:d}s}".format(item, padding=indent + len(pointed) + len(item)) for item in iterable)
        return '\n'.join(result)

    @classmethod
    def filter_candidates(cls, candidates, packed_parameters, tree, table):
        '''Critique the arguments in `packed_parameters` against the branch that is given in `candidates`.'''
        args, _ = packed_parameters
        parameters = (arg for arg in args)

        # First we need a closure that's driven simply by the parameter value. This gets
        # priority and will just descend through the tree until nothing is left.
        def critique_unnamed(parameter, branch):
            for F, node in branch:
                parameter_name, index, _ = node
                discard_and_required, critique_and_transform, _ = table[F, index]
                parameter_critique, parameter_transform, _ = critique_and_transform

                # Now we take the parameter value, transform it, and then critique it.
                try: value = parameter_transform(parameter) if parameter_transform else parameter
                except Exception: continue
                if parameter_critique(value) if parameter_critique else True:
                    yield F, node
                continue
            return

        # This function is only needed for processing arguments, because if there aren't any
        # then all the nodes at a 0-height in our tree end up being checked for termination.
        assert(args)

        # Iterate through all of our parameters until we're finished or out of parameters.
        iterable = ((F, tree[index][F]) for F, index in candidates)
        branch = ((F, (name, index, next)) for F, (name, index, next) in iterable if index >= 0)
        for index, parameter in enumerate(parameters):
            candidates = critique_unnamed(parameter, branch)
            branch = ((F, tree[next][F]) for F, (_, _, next) in candidates if next >= 0 and (F, next) in table)
        return ((F, index) for F, (_, index, next) in candidates if index == next or next >= 0)

    # XXX: Apparently things from pycompat are a _significant_ performance hit. Fortunately,
    #      both Py2 and Py3 use the same attributes, and we can use CO_VARARGS as a default.

    @classmethod
    def filter_args(cls, packed_parameters, tree, table, CO_VARARGS=pycompat.co_flags.CO_VARARGS):
        '''Critique the arguments from `packed_parameters` using the provided `tree` and `table`.'''
        args, _ = packed_parameters

        # If there are some parameters, then start out by only considering functions
        # which support the number of args we were given as candidates.
        if args:
            count = len(args)
            results = {F for F in tree.get(count - 1, [])}

            # Next, we go through all of the available functions to grab only the ones
            # which can take varargs and are smaller than our arg count.
            iterable = ((F, (F.__code__)) for F in tree.get(0, []))
            unknowns = {F for F, c in iterable if (c.co_flags) & CO_VARARGS and (c.co_argcount) <= count}

            # Now we turn them into a branch and then we can process the arguments.
            candidates = ((F, 0) for F in results | unknowns)
            return cls.filter_candidates(candidates, packed_parameters, tree, table)

        # If there are no parameters, then return everything. This really should only be done
        # by multicase.match, but we're doing this here for the sake of the unit-tests.
        branch = tree[0].items()
        return ((F, index) for F, (_, index, next) in branch if index == next or index >= 0)

    @classmethod
    def filter_keywords(cls, candidates, packed_parameters, tree, table):
        '''Critique the keywords from the `packed_parameters` against the branch given in `candidates`.'''
        _, kwds = packed_parameters

        def critique_names(kwds, branch):
            keys = {name for name in kwds}
            for F, node in branch:
                parameter_name, index, _ = node
                discard_and_required, critique_and_transform, wildargs = table[F, index]

                # Extract our sets that are required for the callable to be
                # considered a candidate and filter our keywords depending
                # on whether we're processing named parameters or wild ones.
                discard, required = discard_and_required
                available = keys - discard if wildargs else keys & required

                # If we still have any parameters available and their names
                # don't matter (wild), then critique and what we just consumed.
                if available and wildargs:
                    parameter_critique, parameter_transform, _ = critique_and_transform
                    parameters = (kwds[name] for name in available)
                    transformed = map(parameter_transform, parameters) if parameter_transform else parameters
                    critiqued = all(parameter_critique(parameter) for parameter in transformed) if parameter_critique else True
                    (yield F, node) if critiqued else None

                # If our parameter name is available, then we can critique it.
                elif available and parameter_name in available:
                    parameter_critique, parameter_transform, _ = critique_and_transform
                    try: parameter = parameter_transform(kwds[parameter_name]) if parameter_transform else kwds[parameter_name]
                    except Exception: continue
                    critiqued = parameter_critique(parameter) if parameter_critique else True
                    (yield F, node) if critiqued else None

                # Otherwise this parameter doesn't exist and we can skip over it.
                continue
            return

        # Process as many keywords as we have left...
        branch = ((F, tree[index][F]) for F, index in candidates if (F, index) in table)
        for count in range(len(kwds)):
            critiqued = critique_names(kwds, branch)

            # If processing this keyword resulted in a loop (varargs), then
            # promote it to a wildargs so we can check the rest of the kwargs.
            candidates = ((F, -1 if index == next else index) for F, (_, index, next) in critiqued)
            branch = ((F, tree[-1 if index == next else next][F]) for F, (_, index, next) in critiqued if (F, -1 if index == next else next) in table)
        return candidates

    @classmethod
    def critique_and_transform(cls, F, packed_parameters, tree, table):
        '''Critique and transform the `packed_parameters` for the function `F` returning the resolved parameters and a bias for the number of parameters we needed to transform.'''
        args, kwds = packed_parameters
        counter, results, keywords = 0, [], kwds.copy()

        # First process each of the arguments and add them to our results.
        _, index, _ = tree[0][F]
        for arg in args:
            _, critique_and_transform, _ = table[F, index]
            parameter_critique, parameter_transform, parameter_constraints = critique_and_transform
            parameter = parameter_transform(arg) if parameter_transform else arg
            assert(parameter_critique(parameter) if parameter_critique else True)
            #counter = counter if arg is parameter else counter + 1
            #counter = counter if arg == parameter else counter + 1
            #counter = counter if id(arg) == id(parameter) and parameter_critique else counter + 1 if parameter_critique else counter + 2
            if parameter_critique:
                counter = counter + 2 if id(arg) != id(parameter) else counter if arg.__class__ in parameter_constraints else counter + 1
            else:
                counter = counter + 3
            results.append(parameter)
            _, _, index = tree[index][F]

        # First check if we have any other parameters we need to process
        # because if we don't, then we can just quit while we're ahead.
        if not keywords and (F, index) not in table:
            return results, keywords, counter
        assert((F, index) in table)

        # Now since we have keywords left to process, we need to ensure
        # that we still have parameters to complete or we need to promote
        # ourselves to -1 so that we can critique the keywords leftover.
        _, index, next = tree[index][F]
        index = -1 if index == next else index if (F, next) in table else index

        # Now we can process the rest of our function arguments using whatever
        # keywords that are available until our index becomes less than 0.
        while index >= 0 and (F, index) in table:
            name, index, next = tree[index][F]
            _, critique_and_transform, wild = table[F, index]
            parameter_critique, parameter_transform, parameter_constraints = critique_and_transform
            if index >= 0 and name and not wild:
                arg = keywords.pop(name)
                parameter = parameter_transform(arg) if parameter_transform else arg
                assert(parameter_critique(parameter) if parameter_critique else True)
                #counter = counter if arg is parameter else counter + 1
                #counter = counter if arg == parameter else counter + 1
                #counter = counter if id(arg) == id(parameter) and parameter_critique else counter + 1 if parameter_critique else counter + 2
                if parameter_critique:
                    counter = counter + 2 if id(arg) != id(parameter) else counter if arg.__class__ in parameter_constraints else counter + 1
                else:
                    counter = counter + 3
                results.append(parameter)
            index = next

        # Despite this assertion not being exhaustive, if we ended up with some
        # keywords leftover then our function and index should be in the table.
        assert((F, index) in table if keywords else True)

        # That should be all of our named arguments, so whatever is left should
        # be the keyword arguments that belong to the wildargs candidates.
        return results, keywords, counter

    @classmethod
    def ordered(cls, candidates, tree, table):
        '''Yield the given `candidates` in the correct order using `tree` and `table`.'''
        iterable = reversed(sorted(candidates, key=operator.itemgetter(1)))
        items = [ item for item in iterable ]

        # First we yield all of the items that have successfully terminated.
        iterable = ( item for item in items if item not in table )
        for F, index in iterable:
            yield F, index

        # Now we can yield the callable that we resolved the most parameters with.
        count, items = 0, [item for item in items if item in table]
        for F, index in items[count:]:
            yield F, index
            count += 1

        # Afterwards, we just yield the rest which should all be wildarg parameters.
        for F, index in items[count:]:
            yield F, index
        return

    @classmethod
    def unbiased(cls, packed_parameters, candidates, tree, table):
        '''Yield the callable and transformed `packed_parameters` from `candidates` using `tree` and `table`.'''
        for F, index in candidates:
            args, kargs, bias = cls.critique_and_transform(F, packed_parameters, tree, table)
            yield F, (args, kargs)
        return

    @classmethod
    def preordered(cls, packed_parameters, candidates, tree, table):
        '''Yield the callable and transformed `packed_parameters` from `candidates` using `tree` and `table` in the correct order.'''
        results = {}
        [ results.setdefault(index, []).append(F) for F, index in candidates ]

        order = [index for index in reversed(sorted(results))]
        for index in order:
            items = [ F for F in results[index] if (F, index) not in table ]

            # If we have more than one match, then we need to pre-sort this
            # by whatever their bias is so that we choose the right one.
            if len(items) > 1:
                biased, iterable = {}, (cls.critique_and_transform(F, packed_parameters, tree, table) for F in items)
                #biased = {bias : (F, (args, kwds)) for F, (args, kwds, bias) in zip(items, iterable) }
                [ biased.setdefault(bias, []).append((F, (args, kwds))) for F, (args, kwds, bias) in zip(items, iterable) ]
                ordered = itertools.chain(*(biased[key] for key in sorted(biased)))

            # Otherwise, we don't need to sort and can take the first one.
            else:
                iterable = (cls.critique_and_transform(F, packed_parameters, tree, table) for F in items)
                ordered = ((F, (args, kwds)) for F, (args, kwds, _) in zip(items, iterable))

            # Now we have the biased order and the parameters to use, so yield
            # them to the caller so that it can actually be executed.
            for F, packed in ordered:
                yield F, packed

            # Now we iterate through the results that actually do exist
            # because they're either variable-length parameters or wild.
            items = [ F for F in results[index] if (F, index) in table ]

            # Similarly, if we have more than one match here, then we need
            # to critique_and_transform the parameters and sort by bias.
            if len(items) > 1:
                biased, iterable = {}, (cls.critique_and_transform(F, packed_parameters, tree, table) for F in items)
                #biased = {bias : (F, (args, kargs)) for F, (args, kargs, bias) in zip(items, iterable) }
                [ biased.setdefault(bias, []).append((F, (args, kwds))) for F, (args, kwds, bias) in zip(items, iterable) ]
                ordered = itertools.chain(*(biased[key] for key in sorted(biased)))

            # There's only one match, so that's exactly what we'll return.
            else:
                iterable = (cls.critique_and_transform(F, packed_parameters, tree, table) for F in items)
                ordered = ((F, (args, kwds)) for F, (args, kwds, _) in zip(items, iterable))

            # Yield what we found and continue to the next match.
            for F, packed in ordered:
                yield F, packed
            continue
        return

    # For the following methods, we could expose another decorator that allows
    # one to specifically update the critique_and_transform field inside the
    # parameter table, but for simpliciy (and backwards compatibility) we only
    # use a single decorator and explicitly transform the type with these.

    @classmethod
    def parameter_critique(cls, *types):
        '''Return a callable that critiques its parameter for any of the given `types`.'''

        # If we have some types, then gather them into a set to access them in O(1).
        if types:
            unsorted_types = {item for item in types}

        # If there are no types, then we can bail since no types means anything is valid.
        else:
            return None

        # Filter our types for things that are not actual types. This is okay since we
        # should be using unsorted_types to check whether to include our conditions and
        # we need this so that we can use the types we were given with isinstance().
        filtered = tuple(item for item in unsorted_types if isinstance(item, type))
        if 1 < operator.sub(*reversed(sorted(map(len, [unsorted_types, filtered])))):
            invalid = unsorted_types - {item for item in itertools.chain(filtered, [callable])}
            parameters = [item.__name__ if isinstance(item, type) else item.__name__ if item in {callable} else "{!r}".format(item) for item in types]
            raise internal.exceptions.InvalidParameterError(u"{:s}.parameter_critique({:s}) : Refusing to critique a parameter using {:s} other than a type ({:s}).".format('.'.join([__name__, cls.__name__]), ', '.join(parameters), 'an object' if len(invalid) == 1 else 'objects', ', '.join(map("{!r}".format, invalid))))
        types = filtered

        # Add our default condition that ensures that the parameter is a concrete type.
        Finstance = lambda item, types=types: isinstance(item, types)
        conditions = [Finstance]

        # Add other conditions in case the type can be transformed to the correct one.
        if {item for item in internal.types.integer} & unsorted_types:
            conditions.append(lambda item: hasattr(item, '__int__'))

        # XXX: there's literally no reason to detect parameters that can be coerced to a string.
        #if {item for item in internal.types.string} & unsorted_types:
        #    conditions.append(lambda item: hasattr(item, '__str__'))

        if callable in unsorted_types:
            conditions.append(callable)

        # Now we need to determine whether we combine our tests or only need the first one.
        Fany = lambda item, conditions=conditions: any(F(item) for F in conditions)
        return Fany if len(conditions) > 1 else Finstance

    @classmethod
    def parameter_transform(cls, *types):
        '''Return a callable that transforms its parameter to any of the given `types`.'''
        unsorted_types = {item for item in types}

        # If there are no types, then we can bail here because there's no transform required.
        if not unsorted_types:
            return None

        # Filter our types so that we can use them with isinstance() as we'll be
        # using the unsorted_types set to check for type membership.
        filtered = tuple(item for item in unsorted_types if isinstance(item, type))
        if 1 < operator.sub(*reversed(sorted(map(len, [unsorted_types, filtered])))):
            invalid = unsorted_types - {item for item in itertools.chain(filtered, [callable])}
            parameters = [item.__name__ if isinstance(item, type) else item.__name__ if item in {callable} else "{!r}".format(item) for item in types]
            raise internal.exceptions.InvalidParameterError(u"{:s}.parameter_transform({:s}) : Refusing to transform a parameter using {:s} other than a type ({:s}).".format('.'.join([__name__, cls.__name__]), ', '.join(parameters), 'an object' if len(invalid) == 1 else 'objects', ', '.join(map("{!r}".format, invalid))))
        types = filtered

        # Create a list that includes the condition for a transformation and the
        # transformation itself. If it's not one of these, then we leave it alone.
        transformers = []

        # Figure out the conditions that require us to avoid transforming the item.
        if callable in unsorted_types and len(unsorted_types) == 1:
            transformers.append((None, callable))

        # If there's no callables in our unsorted_types, then we can just use isinstance.
        elif callable not in unsorted_types:
            transformers.append((None, lambda item, types=types: isinstance(item, types)))

        # Otherwise there's some types and a callable that we need to split into two transformations.
        else:
            transformers.append((None, lambda item, types=types: isinstance(item, types)))
            transformers.append((None, callable))

        # Figure out whether we need to add additional transformations...just in case.
        if {item for item in internal.types.integer} & unsorted_types:
            transformers.append((int, lambda item: hasattr(item, '__int__')))

        # XXX: i'm pretty much just showing off here, as there's literally no reason to attempt string coercion.
        #if {item for item in internal.types.string} & unsorted_types:
        #    transformers.append((unicode if str == bytes else str, lambda item: hasattr(item, '__str__')))

        # Now we figure out if we need to do any actual transformations by checking whether the
        # number of transformers we collected is larger than 1. This is because the first transformer
        # will always be the identity function when the item type is correct.
        Ftransform = lambda item, transformers=transformers: next((F(item) if F else item for F, condition in transformers if condition(item)), item)
        return Ftransform if len(transformers) > 1 else None

    # XXX: Our main decorator that is responsible for updating the decorated function.
    @classmethod
    def add(cls, callable, constraints, tree, table):
        '''Add the `callable` with the specified type `constraints` to both the `tree` and `table`.'''
        args, kwargs, packed = pycompat.function.arguments(callable)
        varargs, wildargs = packed

        Fflattened_constraints = lambda types: {item for item in cls.flatten(types if isinstance(types, internal.types.unordered) else [types])}

        # Extract the parameter names and the types that the callable was
        # decorated with so that we can generate the functions used to
        # transform and critique the value that determines its validity.
        critique_and_transform = []
        for name in args:
            t = constraints.pop(name, ())
            Fcritique, Ftransform = cls.parameter_critique(*t), cls.parameter_transform(*t)
            critique_and_transform.append((Fcritique, Ftransform, Fflattened_constraints(t)))

        # Generate two sets that are used to determine what parameter names
        # are required for this wrapped function to still be considered.
        discard_and_required = []
        for index, name in enumerate(args):
            discard = {item for item in args[:index]}
            required = {item for item in args[index:]}
            discard_and_required.append((discard, required))

        # Zip up our parameters with both our critique_and_transform and
        # discard_and_required lists so we can build a tree for each parameter.
        items = [packed for packed in zip(enumerate(args), discard_and_required, critique_and_transform)]
        for index_name, discard_and_required, critique_and_transform in items:
            index, name = index_name
            assert(index_name not in table)
            table[callable, index] = discard_and_required, critique_and_transform, wildargs if wildargs == name else ''
            tree.setdefault(index, {})[callable] = name, index, 1 + index

        # We should be done, but in case there's var args or wild args (keywords), then
        # we'll need to create some cycles within our tree and table. None of these entries
        # hold anything of value, but they need to hold something.. So we create some defaults.
        discard_and_required = {name for name in args}, {name for name in []}
        critique_and_explode = operator.truth, lambda item: False, ()
        critique_and_continue = operator.truth, lambda item: True, ()

        # If there are no parameters whatsoever, then we need a special case
        # which gets used at the first pass of our parameter checks. Essentially
        # we treat this as a vararg, but without the loop. This way if it does
        # turn out to be a vararg or wildarg, it will get fixed to add the loop.
        if not args:
            discard_and_impossible = {name for name in args}, {None}

            # If we don't have any parameters, then our first parameter should
            # immediately fail. If we're variable-length'd or wild, then the
            # conditionals that follow this will overwrite this with a loop.
            table[callable, len(args)] = discard_and_impossible, critique_and_explode, ''
            tree.setdefault(len(args), {})[callable] = '', 0, -1

        # If both are selected, then we need to do some connections here.
        if varargs and wildargs:
            tvar, twild = constraints.pop(varargs, ()), constraints.pop(wildargs, ())

            # Since this callable is variable-length'd, we create a loop in our tree
            # and table so that we can consume any number of parameters.
            Fcritique, Ftransform = cls.parameter_critique(*tvar), cls.parameter_transform(*tvar)
            critique_and_transform = Fcritique, Ftransform, Fflattened_constraints(tvar)

            table[callable, len(args)] = discard_and_required, critique_and_transform, wildargs
            tree.setdefault(len(args), {})[callable] = varargs, len(args), len(args)

            # Since the callable is also wild, we need to create a loop outside the
            # count of parameters (-1). This way we can promote a loop to this path.
            Fcritique, Ftransform = cls.parameter_critique(*twild), cls.parameter_transform(*twild)
            critique_and_transform = Fcritique, Ftransform, Fflattened_constraints(twild)

            tree.setdefault(-1, {})[callable] = wildargs, -1, -1
            table[callable, -1] = discard_and_required, critique_and_transform, wildargs

        # If there's variable-length parameters, then we simply need to create a loop.
        elif varargs:
            t = constraints.pop(varargs, ())
            Fcritique, Ftransform = cls.parameter_critique(*t), cls.parameter_transform(*t)
            critique_and_transform = Fcritique, Ftransform, Fflattened_constraints(t)

            # We can't really match against the parameter name with variable-length
            # parameters, so we add it as a loop for an empty string (unnamed).
            tree.setdefault(len(args), {})[callable] = varargs, len(args), len(args)
            table[callable, len(args)] = discard_and_required, critique_and_transform, ''

        # Pop out the wild (keyword) parameter type from our decorator parameters.
        elif wildargs:
            t = constraints.pop(wildargs, ())
            Fcritique, Ftransform = cls.parameter_critique(*t), cls.parameter_transform(*t)
            critique_and_transform = Fcritique, Ftransform, Fflattened_constraints(t)

            # We need to go through our type parameters and update our table
            # so that it includes any wild keyword parameters.
            tree.setdefault(-1, {})[callable] = wildargs, -1, -1
            table[callable, -1] = discard_and_required, critique_and_transform, wildargs

            # Create our sentinel entry in the tree so that when we run out
            # of args, we transfer to the keyword parameters (-1) to continue.
            tree.setdefault(len(args), {})[callable] = '', len(args), -1
            table[callable, len(args)] = discard_and_required, critique_and_continue, wildargs

        return callable

    @classmethod
    def flatten(cls, iterable):
        '''Take the provided `iterable` (or tree) and then yield each individual element resulting in it being "flattened".'''
        duplicates = {item for item in []}
        for item in iterable:
            if isinstance(item, internal.types.unordered):
                for item in cls.flatten(item):
                    if item in duplicates:
                        continue
                    yield item
                    duplicates |= {item}
                continue
            if item in duplicates:
                continue
            yield item
            duplicates |= {item}
        return

    @classmethod
    def render_documentation(cls, function, constraints, ignored):
        '''Render the documentation for a `function` using the given `constraints` while skipping over any `ignored` parameters.'''
        args, defaults, (star, starstar) = pycompat.function.arguments(function)
        parameters = [name for name in itertools.chain(args, [star, starstar]) if name]
        prototype = cls.prototype(function, constraints, ignored)
        documentation = function.__doc__ or ''
        lines = documentation.split('\n')
        constraint_order = [constraints.get(arg, ()) for arg in parameters]
        return prototype, [item.strip() for item in lines] if documentation.strip() else [], (lambda *args: args)(*constraint_order)

    # Create a dictionary to bias the order of our documentation so that
    # custom or more complicated types tend to come first.
    documentation_bias = {constraint : 1 for constraint in itertools.chain(internal.types.ordered, internal.types.unordered)}
    documentation_bias.update({constraint : 2 for constraint in itertools.chain(internal.types.integer, internal.types.string)})

    @classmethod
    def sorted_documentation(cls, descriptions):
        '''Return the provided `descriptions` in the order that was used to generate their documentation.'''

        # First we need to look at the documentation and extract the number of lines.
        iterable = ((F, pycompat.function.documentation(F) or '') for F in descriptions)
        stripped = ((F, string.strip()) for F, string in iterable)
        newlines = {F : string.count('\n') for F, string in stripped}

        # Now we extract the constraints for each parameter so that we can calculate the
        # number of parameters along with a bias based on the constraints.
        items = [(F, constraints) for F, (_, _, constraints) in descriptions.items()]
        counts = {F : len(constraints) for F, constraints in items}
        bias = {F : sum(max((cls.documentation_bias.get(item, 0) for item in items) if items else [0]) for items in constraints) for F, constraints in items}

        # Afterwards we can sort by number of lines, number of parameters, and then constraint bias.
        items = [((newlines[F], counts[F], bias[F]), F) for F in descriptions]
        return [F for _, F in sorted(items, key=operator.itemgetter(0))]

    @classmethod
    def prototype(cls, function, constraints={}, ignored={item for item in []}):
        '''Generate a prototype for the given `function` and `constraints` while skipping over the `ignored` argument names.'''
        args, defaults, (star, starstar) = pycompat.function.arguments(function)

        def Femit_arguments(names, constraints, ignored):
            '''Yield a tuple for each individual parameter composed of the name and its constraints.'''

            # Iterate through all of our argument names. If any of them are within
            # our ignored items, however, then we can simply skip over them.
            for item in names:
                if item in ignored:
                    continue

                # If the current argument name is not within our constraints, then
                # we only have to yield the argument name and move on.
                if item not in constraints:
                    yield item, None
                    continue

                # Figure out which constraint to use for each item, and yield how
                # it should be represented back to the caller.
                constraint = constraints[item]
                if isinstance(constraint, internal.types.type) or constraint in {internal.types.callable}:
                    yield item, constraint.__name__
                elif hasattr(constraint, '__iter__'):
                    yield item, '|'.join(type.__name__ for type in cls.flatten(constraint))
                else:
                    yield item, "{!s}".format(constraint)
                continue
            return

        # Log any multicased functions that accidentally define type constraints for parameters
        # which don't actually exist. This is specifically done in order to aid debugging.
        unavailable = {constraint_name for constraint_name in constraints.keys()} - {argument_name for argument_name in itertools.chain(args, filter(None, [star, starstar]))}
        if unavailable:
            co = pycompat.function.code(function)
            co_fullname, co_filename, co_lineno = '.'.join([function.__module__, function.__name__]), os.path.relpath(co.co_filename, idaapi.get_user_idadir()), co.co_firstlineno
            proto_s = "{:s}({:s}{:s}{:s})".format(co_fullname, ', '.join(args) if args else '', ", *{:s}".format(star) if star and args else "*{:s}".format(star) if star else '', ", **{:s}".format(starstar) if starstar and (star or args) else "**{:s}".format(starstar) if starstar else '')
            path_s = "{:s}:{:d}".format(co_filename, co_lineno)
            logging.warning(u"{:s}({:s}): Unable to constrain the type in {:s} for parameter{:s} ({:s}) at {:s}.".format('.'.join([__name__, cls.__name__]), co_fullname, proto_s, '' if len(unavailable) == 1 else 's', ', '.join(unavailable), path_s))

        # Return the prototype for the current function with the provided parameter constraints.
        iterable = (item if parameter is None else "{:s}={:s}".format(item, parameter) for item, parameter in Femit_arguments(args, constraints, ignored))
        items = iterable, ["*{:s}".format(star)] if star else [], ["**{:s}".format(starstar)] if starstar else []
        return "{:s}({:s})".format(fattribute('__qualname__', pycompat.function.name(function))(function), ', '.join(itertools.chain(*items)))

    @classmethod
    def match(cls, packed_parameters, tree, table):
        '''Use the provided `packed_parameters` to find a matching callable in both `tree` and `table`.'''
        args, kwargs = packed_parameters
        candidates = cls.filter_args(packed_parameters, tree, table)

        # If there's no other filters, then we filter our candidates
        # by culling out everything that can still take parameters.
        if not kwargs:
            iterable = ((F, tree[index][F]) for F, index in candidates)
            branch = [(F, name, index, next) for F, (name, index, next) in iterable if next <= len(args)]

            # Now we have a branch containing everything that we care about. So, all we really
            # need to do here is collect our results if we have any that are available.
            results = [(F, next) for F, name, index, next in branch if (F, next) not in table]

            # In case we didn't get any results, then we move onto the next branch so that we
            # can grab the next varargs or wildargs candidates that are still available.
            nextbranch = [(F, tree[next][F]) for F, name, index, next in branch if (F, next) in table]
            vars = [(F, next) for F, (name, index, next) in nextbranch if index == next and index <= len(args)]
            wild = [(F, next) for F, (name, index, next) in nextbranch if index != next and next < 0]

            # That was everything, so we just need to return them in the correct order.
            return results + vars + wild

        # If we had some args that we ended up processing, then we need to shift them if there's
        # still some parameters or promote them to keywords to do the final filtering pass.
        elif args:
            iterable = ((F, tree[index][F]) for F, index in candidates if (F, index) in table)
            candidates = ((F, -1 if index == next else next) for F, (_, index, next) in iterable)
            #candidates = [(F, -1 if index == next else index) for F, (_, index, next) in iterable]

        # Now each candidate should be at the right place in their tree and we can filter keywords.
        results = cls.filter_keywords(candidates, packed_parameters, tree, table)

        # Last thing to do is to take our results, filter their matches, sort them by their
        # and then we can return them to the caller to actually use them.
        iterable = ((F, tree[index][F]) for F, index in results)
        return [(F, next) for F, (_, index, next) in iterable if next < 0 or (F, next) not in table]

    @classmethod
    def new_wrapper(cls, func, cache, Fmissing=None, Fdebug_candidates=None):
        '''Create a new wrapper that will determine the correct function to call.'''
        tree, table = cache

        ## Define the wrapper for the function that we're decorating. This way whenever the
        ## decorated function gets called, we can search for one that matches the correct
        ## constraints and dispatch into it with the correctly transformed parameters.
        def F(*arguments, **keywords):
            packed_parameters = arguments, keywords
            candidates = cls.match(packed_parameters, tree, table)
            iterable = cls.preordered(packed_parameters, candidates, tree, table) if len(candidates) > 1 else cls.unbiased(packed_parameters, candidates, tree, table)

            # Extract our first match if we were able to find one. If not, then pass what
            # we tried to match to the missing-hook to complain about it.
            result = next(iterable, None)
            if result is None:
                if Fmissing is not None:
                    return Fmissing(packed_parameters, tree, table)
                raise RuntimeError(packed_parameters, tree, table)

            # If our debug-hook is defined, then pass our matches to it so that it can be
            # dumped to the screen or stashed somewhere to assist debugging.
            if Fdebug_candidates is not None:
                res = Fdebug_candidates(itertools.chain([result], iterable), packed_parameters, tree, table)
                assert(res is None)

            # We got a callable, so we just need to call it with our parameters.
            F, (args, kwds) = result
            return F(*args, **kwds)

        # First, we need to swap out the original code object with the one from the closure
        # that we defined. In order to preserve information within the backtrace, we just
        # make a copy of all of the relevant code properties.
        f, c = F, pycompat.function.code(F)
        cargs = c.co_argcount, c.co_nlocals, c.co_stacksize, c.co_flags, \
                c.co_code, c.co_consts, c.co_names, c.co_varnames, \
                c.co_filename, '.'.join([func.__module__, pycompat.function.name(func)]), \
                c.co_firstlineno, c.co_lnotab, c.co_freevars, c.co_cellvars
        newcode = pycompat.code.new(cargs, pycompat.code.unpack_extra(c))

        # Now we can use the new code object that we created in order to create a function,
        # assign the previous name and documentation into it, and return it.
        result = pycompat.function.new(newcode, pycompat.function.globals(f), pycompat.function.name(f), pycompat.function.defaults(f), pycompat.function.closure(f))
        pycompat.function.set_name(result, pycompat.function.name(func))
        pycompat.function.set_documentation(result, pycompat.function.documentation(func))
        setattr(result, '__qualname__', func.__qualname__) if hasattr(func, '__qualname__') else None
        return result

class alias(object):
    """
    This class is used to generate a function that will be replaced with a
    reference to another function. This has the effect of returning an alias
    to the target function. The returned function will have its documentation
    updated to inform the caller the function that it is an alias of.
    """
    def __new__(cls, other, klass=None):
        if isinstance(other, type):
            return cls.namespace_wrapper(other, klass)

        cons, func = pycompat.function.constructor(other), pycompat.function.extract(other)
        qualname = fattribute('__qualname__', None)(func)
        if klass:
            module = [func.__module__, klass]
        elif isinstance(other, (staticmethod, classmethod)):
            stripped = qualname[:-len(pycompat.function.name(func))].rstrip('.') if qualname else None
            module = [func.__module__, stripped] if stripped else [func.__module__]
        elif isinstance(other, internal.types.method):
            method_klass = pycompat.method.type(func)
            module = [func.__module__, klass if klass else fattribute('__qualname__', method_klass.__name__)(method_klass)]
        else:
            stripped = qualname[:-len(pycompat.function.name(func))].rstrip('.') if qualname else None
            module = [func.__module__, stripped] if stripped else [func.__module__]

        document = "Alias for `{:s}`.".format('.'.join(module + [pycompat.function.name(func)]))
        res = cls.new_wrapper(func, document)
        return cons(res)

    @classmethod
    def new_wrapper(cls, func, document):
        wrapper = lambda *arguments, **keywords: func(*arguments, **keywords)

        # functools.update_wrapper doesn't actually update any of the things
        # we wanted it to, so we pretty much have to do it all ourselves.
        pycompat.function.set_name(wrapper, pycompat.function.name(func))
        if hasattr(func, '__module__'):
            wrapper.__module__ = func.__module__

        res = functools.update_wrapper(wrapper, func)
        pycompat.function.set_documentation(res, document)
        return res

    @classmethod
    def namespace_wrapper(cls, other, klass):
        func = other.__new__
        qualname = fattribute('__qualname__', None)(other)

        # allocate a closure that calls our original "func" so that we
        # can udpate its attributes to ensure that it looks the same.
        wrapper = lambda *arguments, **keywords: func(other, *arguments, **keywords)

        if klass:
            module = [func.__module__, klass]
        else:
            assert(not isinstance(func, internal.types.method))
            module = [func.__module__, qualname] if qualname else [func.__module__, other.__name__]
        document = "Alias for `{:s}`.".format('.'.join(module + [pycompat.function.name(func)]))

        # copy-pasta
        pycompat.function.set_name(wrapper, pycompat.function.name(func))
        if hasattr(func, '__module__'):
            wrapper.__module__ = func.__module__

        res = functools.update_wrapper(wrapper, func)
        pycompat.function.set_documentation(res, document)
        return res

### matcher class helper

# FIXME: figure out how to match against a bounds_t in a non-hacky way
class matcher(object):
    """
    An object that allows one to match or filter a list of things in an
    sort of elegant way.
    """

    def __init__(self):
        self.__predicate__ = {}
    def __attrib__(self, *attributes):
        if not attributes:
            return lambda item: item
        res = [(operator.attrgetter(callable_or_attribute) if isinstance(callable_or_attribute, internal.types.string) else callable_or_attribute) for callable_or_attribute in attributes]
        return fcompose(*res) if len(res) > 1 else res[0]
    def attribute(self, type, *attribute):
        attr = self.__attrib__(*attribute)
        Funsortable = finstance(internal.types.string, internal.types.integer, internal.types.float, internal.types.bytes, internal.types.bool, internal.types.none)
        self.__predicate__[type] = lambda target: fcompose(attr, fcondition(Funsortable)(functools.partial(functools.partial, operator.eq), functools.partial(functools.partial, operator.contains))(target))
    def mapping(self, type, function, *attribute):
        attr = self.__attrib__(*attribute)
        mapper = fcompose(attr, function)
        self.__predicate__[type] = lambda target: fcompose(mapper, functools.partial(operator.eq, target))
    def boolean(self, type, function, *attribute):
        attr = self.__attrib__(*attribute)
        self.__predicate__[type] = lambda target: fcompose(attr, functools.partial(function, target))
    def combinator(self, type, function, *attribute):
        attr = self.__attrib__(*attribute)
        self.__predicate__[type] = fcompose(function, functools.partial(fcompose, attr))
    def predicate(self, type, *attribute):
        attr = self.__attrib__(*attribute)
        self.__predicate__[type] = functools.partial(fcompose, attr)
    def match(self, type, value, iterable):
        if type not in self.__predicate__:
            cls, available, description = self.__class__, sorted(self.__predicate__), "...{:d} element{:s}".format(len(iterable), '' if len(iterable) == 1 else 's') if hasattr(iterable, '__len__') else '...' if hasattr(iterable, '__iter__') else "{!r}".format(iterable)
            raise internal.exceptions.InvalidMatchTypeError(u"{:s}.match({!r}, {!r}, {!s}) : The requested filter (\"{:s}\") is not within the list of available filters ({:s}).".format('.'.join([__name__, cls.__name__]), type, value, description, string.escape(type, '"'), ', '.join(available)))
        matcher = self.__predicate__[type](value)
        return (item for item in iterable if matcher(item))
    def alias(self, target, type):
        self.__predicate__[target] = self.__predicate__[type]

### character processing (escaping and unescaping)
class character(object):
    """
    This namespace is responsible for performing actions on individual
    characters such as detecting printability or encoding them in a
    form that can be evaluated.
    """
    class const(object):
        ''' Constants '''
        import string as _string, unicodedata as _unicodedata

        backslash = u'\\'

        # character mappings to escaped versions
        mappings = {
            u'\a' : u'\\a',
            u'\b' : u'\\b',
            u'\t' : u'\\t',
            u'\n' : u'\\n',
            u'\v' : u'\\v',
            u'\f' : u'\\f',
            u'\r' : u'\\r',
            u'\0' : u'\\0',
            u'\1' : u'\\1',
            u'\2' : u'\\2',
            u'\3' : u'\\3',
            u'\4' : u'\\4',
            u'\5' : u'\\5',
            u'\6' : u'\\6',
            #u'\7' : u'\\7',     # this is the same as '\a'
        }

        # inverse mappings of characters plus the '\7 -> '\a' byte
        inverse = { v : k for k, v in itertools.chain([(u'\7', u'\\7')], mappings.items()) }

        # whitespace characters as a set
        whitespace = { ch for ch in _string.whitespace }

        # printable characters as a set (spaces are the only whitespace that we consider as printable)
        printable = { ch for ch in _string.printable } - whitespace | {u' '}

        # hexadecimal digits as a lookup
        hexadecimal = { ch : i for i, ch in enumerate(_string.hexdigits[:0x10]) }

    @classmethod
    def asciiQ(cls, ch):
        '''Returns whether an ascii character is printable or not.'''
        return operator.contains(cls.const.printable, ch)

    @classmethod
    def unicodeQ(cls, ch):
        '''Returns whether a unicode character is printable or not.'''
        cat = cls.const._unicodedata.category(ch)
        return cat[0] != 'C'

    @classmethod
    def whitespaceQ(cls, ch):
        '''Returns whether a character represents whitespace or not.'''
        return operator.contains(cls.const.whitespace, ch)

    @classmethod
    def mapQ(cls, ch):
        '''Returns whether a character is mappable or not.'''
        return operator.contains(cls.const.mappings, ch)

    @classmethod
    def map(cls, ch):
        '''Given a mappable character, return the string that emits it.'''
        return operator.getitem(cls.const.mappings, ch)

    @classmethod
    def hexQ(cls, ch):
        '''Returns whether a character is a hex digit or not.'''
        return operator.contains(cls.const.hexadecimal, ch)

    @classmethod
    def to_hex(cls, integer):
        '''Given an integer, return the hex digit that it represents.'''
        inverse = { digit : char for char, digit in cls.const.hexadecimal.items() }
        if integer in inverse:
            return operator.getitem(inverse, integer)
        raise ValueError(integer)

    @classmethod
    def of_hex(cls, digit):
        '''Given a hex digit, return it as an integer.'''
        return operator.getitem(cls.const.hexadecimal, digit.lower())

    @classmethod
    def escape(cls, result):
        '''Return a generator that escapes all non-printable characters and sends them to `result`.'''

        # begin processing any input that is fed to us
        while True:
            ch = (yield)
            n = ord(ch)

            # check if character has an existing escape mapping
            if cls.mapQ(ch):
                for ch in cls.map(ch):
                    result.send(ch)

            # check if character is a backslash
            elif operator.contains(cls.const.backslash, ch):
                result.send(cls.const.backslash)
                result.send(ch)

            # check if character is printable (py2 and unicode)
            elif sys.version_info.major < 3 and isinstance(ch, unicode) and cls.unicodeQ(ch):
                result.send(ch)

            # check if character is printable (py3 and unicode)
            elif 2 < sys.version_info.major and isinstance(ch, str) and cls.unicodeQ(ch):
                result.send(ch)

            # check if character is printable (ascii)
            elif isinstance(ch, internal.types.string) and cls.asciiQ(ch):
                result.send(ch)

            # check if character is a single-byte ascii
            elif n < 0x100:
                result.send(cls.const.backslash)
                result.send(u'x')
                result.send(cls.to_hex((n & 0xf0) // 0x10))
                result.send(cls.to_hex((n & 0x0f) // 0x01))

            # check that character is an unprintable unicode character
            elif n < 0x10000:
                result.send(cls.const.backslash)
                result.send(u'u')
                result.send(cls.to_hex((n & 0xf000) // 0x1000))
                result.send(cls.to_hex((n & 0x0f00) // 0x0100))
                result.send(cls.to_hex((n & 0x00f0) // 0x0010))
                result.send(cls.to_hex((n & 0x000f) // 0x0001))

            # maybe the character is an unprintable long-unicode character
            elif n < 0x110000:
                result.send(cls.const.backslash)
                result.send(u'U')
                result.send(cls.to_hex((n & 0x00000000) // 0x10000000))
                result.send(cls.to_hex((n & 0x00000000) // 0x01000000))
                result.send(cls.to_hex((n & 0x00100000) // 0x00100000))
                result.send(cls.to_hex((n & 0x000f0000) // 0x00010000))
                result.send(cls.to_hex((n & 0x0000f000) // 0x00001000))
                result.send(cls.to_hex((n & 0x00000f00) // 0x00000100))
                result.send(cls.to_hex((n & 0x000000f0) // 0x00000010))
                result.send(cls.to_hex((n & 0x0000000f) // 0x00000001))

            # if we're here, then we have no idea what kind of character it is
            else:
                raise internal.exceptions.InvalidFormatError(u"{:s}.unescape({!s}) : Unable to determine how to escape the current character code ({:#x}).".format('.'.join([__name__, cls.__name__]), result, n))

            continue
        return

    @classmethod
    def unescape(cls, result):
        '''Return a generator that reads characters from an escaped string, unescapes/evaluates them, and then the unescaped character to `result`.'''

        # enter our processing loop for each character
        while True:
            ch = (yield)

            # okay, we got a backslash, so let's go...
            if ch == cls.const.backslash:
                t = (yield)

                # check if our character is in our inverse mappings
                if operator.contains(cls.const.inverse, cls.const.backslash + t):
                    ch = operator.getitem(cls.const.inverse, cls.const.backslash + t)
                    result.send(ch)

                # check if our character is a backslash
                elif operator.contains(cls.const.backslash, t):
                    result.send(cls.const.backslash)

                # check if the 'x' prefix is specified, which represents a hex digit
                elif t == u'x':
                    hb, lb = (yield), (yield)
                    if any(not cls.hexQ(b) for b in {hb, lb}):
                        raise internal.exceptions.InvalidFormatError(u"{:s}.unescape({!s}) : Expected the next two characters ('{:s}', '{:s}') to be hex digits for an ascii character.".format('.'.join([__name__, cls.__name__]), result, string.escape(hb, '\''), string.escape(lb, '\'')))

                    # convert the two hex digits into their integral forms
                    h, l = (cls.of_hex(item) for item in [hb.lower(), lb.lower()])

                    # coerce the digits into an ascii character and send the character to our result
                    result.send(six.unichr(
                        h * 0x10 |
                        l * 0x01 |
                    0))

                # if we find a 'u' prefix, then we have a unicode character
                elif t == u'u':
                    hwb, lwb, hb, lb = (yield), (yield), (yield), (yield)
                    if any(not cls.hexQ(b) for b in {hwb, lwb, hb, lb}):
                        raise internal.exceptions.InvalidFormatError(u"{:s}.unescape({!s}) : Expected the next four characters ('{:s}', '{:s}', '{:s}', '{:s}') to be hex digits for a unicode character.".format('.'.join([__name__, cls.__name__]), result, string.escape(hwb, '\''), string.escape(lwb, '\''), string.escape(hb, '\''), string.escape(lb, '\'')))

                    # convert the four hex digits into their integral forms
                    hw, lw, h, l = (cls.of_hex(item) for item in [hwb.lower(), lwb.lower(), hb.lower(), lb.lower()])

                    # coerce the digits into a unicode character and send the character to our result
                    result.send(six.unichr(
                        hw * 0x1000 |
                        lw * 0x0100 |
                        h  * 0x0010 |
                        l  * 0x0001 |
                    0))

                # if we find a 'U' prefix, then we have a long unicode character
                elif t == u'U':
                    hzb, lzb, Hwb, Lwb, hwb, lwb, hb, lb = (yield), (yield), (yield), (yield), (yield), (yield), (yield), (yield)
                    if any(not cls.hexQ(b) or cls.of_hex(b) for b in (hzb, lzb)):
                        raise internal.exceptions.InvalidFormatError(u"{:s}.unescape({!s}) : Expected the next two characters ('{:s}', '{:s}') to be zero for a long-unicode character.".format('.'.join([__name__, cls.__name__]), result, string.escape(hzb, '\''), string.escape(lzb, '\'')))
                    if any(not cls.hexQ(b) for b in {Hwb, Lwb, hwb, lwb, hb, lb}) or Hwb not in {'0', '1'}:
                        raise internal.exceptions.InvalidFormatError(u"{:s}.unescape({!s}) : Expected the next six characters ('{:s}', '{:s}', '{:s}', '{:s}', '{:s}', '{:s}') to be hex digits for a long-unicode character.".format('.'.join([__name__, cls.__name__]), result, string.escape(Hwb, '\''), string.escape(Lwb, '\''), string.escape(hwb, '\''), string.escape(lwb, '\''), string.escape(hb, '\''), string.escape(lb, '\'')))

                    # convert the six hex digits into their integral forms
                    Hw, Lw, hw, lw, h, l = (cls.of_hex(item) for item in [Hwb.lower(), Lwb.lower(), hwb.lower(), lwb.lower(), hb.lower(), lb.lower()])

                    # coerce the digits into a unicode character and send the character to our result
                    result.send(six.unichr(
                        Hw * 0x100000 |
                        Lw * 0x010000 |
                        hw * 0x001000 |
                        lw * 0x000100 |
                        h  * 0x000010 |
                        l  * 0x000001 |
                    0))

                else:
                    result.send(t)

            # we haven't received a backslash, so there's nothing to unescape
            else:
                result.send(ch)

            continue
        return

### string casting, escaping and emitting
class string(object):
    """
    IDA takes ascii strings and internally encodes them as UTF8. So
    this class aims to normalize all of these strings by converting
    them into a `unicode` type.
    """

    @classmethod
    def of_2x(cls, string):
        '''Return a string from IDA in a format that is consistent'''
        return None if string is None else string.decode('utf8') if isinstance(string, str) else string

    @classmethod
    def to_2x(cls, string):
        '''Convert a string into a form that IDA will accept.'''
        return None if string is None else string.encode('utf8') if isinstance(string, unicode) else string

    # In Python3, IDA seems to handle the native string-type properly so we can
    # just convert the desired parameter to a string and pass it through the API.

    @classmethod
    def passthrough(cls, string):
        '''Handle all strings both from IDA and to IDA transparently.'''
        return None if string is None else string

    # In older versions of IDA, according to https://hex-rays.com/products/ida/news/7_0/docs/i18n/,
    # the OEM encoding is used on the windows platform with UTF-8 on all of the others. We can get
    # the correct one on windows using ctypes with the `get_codepages` api from the sdk. This api
    # can return a constant, though, so it's up to us to figure out which encoding it actually is.
    # If we're unable to figure anything out, then we fall back to python's "mbcs" encoding which
    # should represent the current windows codepage according to the documentation.

    if idaapi.__version__ < 7.0 and sys.platform == 'win32':
        if hasattr(ida, 'get_codepages'):
            ida.get_codepages.restype, ida.get_codepages.argtypes = ctypes.c_ulong, [ctypes.POINTER(ctypes.c_ulong)]

        class codepage(object):
            """
            This class is used for getting information about the current code page so
            that it can be used to distinguishing how to encode and decode strings into
            the database and out to Python. It is temporary and shouldn't really be used.
            """

            # Now we need to figure out which codepage the disassembler is using.
            @classmethod
            def get_disassembler_codepage(cls):
                '''Return the current codepage that is used by the disassembler.'''
                cp = ctypes.pointer(ctypes.c_ulong(-1))
                return cp.contents.value if ida.get_codepages(cp) == 0 else 1   # CP_ACP(1)

            # ..And we need some function that will convert that default codepage into something python understands.
            @classmethod
            def GetCPInfoExW(cls, CodePage):
                '''Use ctypes to call the "kernel32.dll!GetCPInfoExW" Windows API and return information about the current codepage.'''
                class _cpinfoexW(ctypes.Structure):
                    MAX_LEADBYTES, MAX_DEFAULTCHAR = 12, 2
                    MAX_PATH = 260
                    _fields_ = [
                        ("MaxCharSize", ctypes.c_uint),
                        ("DefaultChar", ctypes.c_ubyte * MAX_DEFAULTCHAR),
                        ("LeadByte", ctypes.c_ubyte * MAX_LEADBYTES),
                        ("UnicodeDefaultChar", ctypes.c_wchar),
                        ("CodePage", ctypes.c_uint),
                        ("CodePageName", ctypes.c_wchar * MAX_PATH)
                    ]
                GetCPInfoExW = ctypes.windll.kernel32.GetCPInfoExW
                GetCPInfoExW.restype, GetCPInfoExW.argtypes = ctypes.c_long, [ctypes.c_uint, ctypes.c_long, ctypes.POINTER(_cpinfoexW)]
                res = _cpinfoexW()
                if not GetCPInfoExW(CodePage, 0, ctypes.pointer(res)):
                    return None
                return res

            # This lookup table is used for mapping a codepage number to a Python encoding,
            # but these encoding aren't guaranteed to be available in all versions of Python.
            codepage_codec_map = {codepage : encoding for codepage, encoding in [
                (1047, 'latin1'), (870, 'latin2'),
                (1141, 'IBM273',), (1142, 'IBM865',), (1146, 'IBM039',), (1149, 'IBM861',),
                (10000, 'mac_roman',), (10001, 'mac_roman',), (10002, 'csbig5',), (10006, 'mac_greek',), (10007, 'mac_cyrillic',), (10008, 'gb2312',), (10029, 'mac_latin2',), (10081, 'mac_turkish',),
                (12000, 'utf-32le'), (12001, 'utf-32be'),
                (20125, 'IBM855'), (20273, 'IBM273'), (20277, 'IBM277'), (20278, 'IBM278'), (20280, 'IBM280'), (20284, 'IBM284'), (20285, 'IBM285'), (20290, 'IBM290'), (20297, 'IBM297'), (20420, 'IBM420'), (20423, 'IBM423'), (20424, 'IBM424'), (20833, 'IBM833'), (20838, 'IBM838'), (20871, 'IBM871'), (20880, 'IBM880'), (20905, 'IBM905'), (20924, 'IBM924'),
                (20932, 'euc-jp'), (51949, 'euc-kr'),
                (20866, 'koi8_r'), (21866, 'koi8_u'),
                (28591, 'iso8859-1'), (28592, 'iso8859-2'), (28593, 'iso8859-3'), (28594, 'iso8859-4'), (28595, 'iso8859-5'), (28596, 'iso8859-6'), (28597, 'iso8859-7'), (28598, 'iso8859-8'), (28599, 'iso8859-9'), (28603, 'iso8859-13'), (28605, 'iso8859-15'), (38598, 'iso8859-8'),
                (50220, 'iso2022-jp'), (50221, 'iso2022-jp-ext'), (50222, 'iso2022-jp'), (50225, 'iso2022_kr'), (50227, 'iso2022_jp'), (50229, 'iso2022_jp'),
                (20936, 'gb2312'), (52936, 'hz-gb-2312'), (54936, 'gb18030'),
                (20127, 'us-ascii'), (65000, 'utf-7'), (65001, 'utf-8'), (65002, 'utf-16'),
            ]}

            @classmethod
            def lookup_codepage(cls, codepage):
                '''Use the given `codepage` to determine the string codec that will be used by Python to encode or decode strings.'''
                encoding = "CP{:03d}".format(codepage)
                try:
                    codec = codecs.lookup(encoding)
                except LookupError:
                    encoding = cls.codepage_codec_map.get(codepage, '')
                else:
                    return codec.name

                # if we couldn't find the code for the codepage, then we
                # need to try again using whatever was in our codec map.
                try:
                    codec = codecs.lookup(encoding)
                except LookupError:
                    return ''
                return codec.name

            # Define a table for describing the default codepage types available from windows.
            windows_codepage_description = {
                0: 'CP_ACP', 1: 'CP_OEMCP', 2: 'CP_MACCP', 3: 'CP_THREAD_ACP', 42: 'CP_SYMBOL',
                12000: 'CP_UTF32LE', 12001: 'CP_UTF32BE', 65000: 'CP_UTF7', 65001: 'CP_UTF8', 65002: 'CP_UTF16',
            }

            @classmethod
            def describe_codepage(cls, codepage):
                '''Return a printable description for the specified `codepage`.'''
                if codepage in cls.windows_codepage_description:
                    return "{:s}({:d})".format(cls.windows_codepage_description[codepage], codepage)
                elif codepage in cls.codepage_codec_map:
                    return cls.codepage_codec_map[codepage]
                return "unknown({:d})".format(codepage)

            @staticmethod
            def return_of_encoding(encoding):
                '''Return a closure that can be used to decode a string from the given `encoding`.'''
                def of(string):
                    '''Convert a string using the codepage of the disassembler to a python string.'''
                    return None if string is None else string.decode(encoding) if isinstance(string, str) else string
                return of

            @staticmethod
            def return_to_encoding(encoding):
                '''Return a closure that can be used to encode a string to the given `encoding`.'''
                def to(string):
                    '''Convert a python string to a string using the codepage of the disassembler.'''
                    return None if string is None else string.encode(encoding) if isinstance(string, unicode) else string
                return to

            def __new__(cls):
                '''Return a tuple of functions that may be used to decode strings from the database and encode strings into the database.'''
                cp = cls.get_disassembler_codepage()
                cpinfoex = cls.GetCPInfoExW(cp)
                if cpinfoex:
                    encoding, description = cls.lookup_codepage(cpinfoex.CodePage), cpinfoex.CodePageName
                else:
                    encoding, description = '', 'Unknown'

                # Now we need to verify that the codec actually exists, because if
                # it doesn't then we need to fallback to something.
                try:
                    codec = codecs.lookup(encoding)
                except LookupError:
                    encoding = 'MBCS' if sys.version_info.major < 3 and sys.version_info.minor < 6 else 'OEM'
                else:
                    encoding = codec.name

                # Okay, that should be it and we just need to log what we figured out.
                logging.info(u"{:s} : Detected codepage {:s} used by disassembler which will result in using the \"{:s}\" string encoding.".format('.'.join([__name__, cls.__name__]), cls.describe_codepage(cp), encoding))
                return cls.return_of_encoding(encoding), cls.return_to_encoding(encoding)

        # Now we should be able to get some functions that will encode and decode strings from the database.
        of, to = map(staticmethod, codepage())

    # Otherwise we should be able to trust that everything is going to be UTF-8.
    else:
        of = of_2x if sys.version_info.major < 3 else passthrough
        to = to_2x if sys.version_info.major < 3 else passthrough

    # dictionary for mapping control characters to their correct forms
    mapping = {
        u'\n' : u'\\n',
        u' ' : u' ',
    }

    @classmethod
    def escape(cls, string, quote=u''):
        """Escape the characters in `string` specified by `quote`.

        Handles both unicode and ascii. Defaults to escaping only
        the unprintable characters.
        """

        # construct a list for anything that gets transformed
        res = internal.interface.collect_t(list, lambda agg, value: agg + [value])

        # instantiate our generator for escaping unprintables in the string
        transform = character.escape(res); next(transform)

        # iterate through each character, sending everything to res
        for ch in (string or u''):

            # check if character is a user-specified quote or a backslash
            if any(operator.contains(set, ch) for set in {quote, u'\\'}):
                res.send(u'\\')
                res.send(ch)

            # check if character has an escape mapping to use
            elif operator.contains(cls.mapping, ch):
                [res.send(item) for item in cls.mapping[ch]]

            # otherwise we can just send it to transform to escape it
            else:
                transform.send(ch)
            continue

        # figure out the correct function that determines how to join the res
        cons = unicode() if sys.version_info.major < 3 and isinstance(string, unicode) else str()
        return cons.join(res.get())

    @classmethod
    def repr(cls, item):
        """Given an item, return the `repr()` of it whilst ensuring that a proper ascii string is returned.

        All unicode strings are encoded to UTF-8 in order to guarantee
        the resulting string can be emitted.
        """

        # Python2 string types (str/bytes and unicode)
        if isinstance(item, internal.types.string) and sys.version_info.major < 3:
            res = cls.escape(item.decode('latin1') if isinstance(item, internal.types.bytes) else item, u'\'')
            if all(ord(ch) < 0x100 for ch in item):
                return u"'{:s}'".format(res)
            return u"u'{:s}'".format(res)

        # Python3 string types (str and bytes)
        elif isinstance(item, internal.types.string):
            res = cls.escape(item, u'\'')
            return u"'{:s}'".format(res)

        elif isinstance(item, internal.types.bytes):
            res = cls.escape(item.decode('latin1'), u'\'')
            return u"b'{:s}'".format(res)

        elif isinstance(item, internal.types.tuple):
            res = map(cls.repr, item)
            return u"({:s}{:s})".format(', '.join(res), ',' if len(item) == 1 else '')

        elif isinstance(item, internal.types.list):
            res = map(cls.repr, item)
            return u"[{:s}]".format(', '.join(res))

        elif isinstance(item, internal.types.set):
            res = map(cls.repr, item)
            return u"set([{:s}])".format(', '.join(res))

        elif isinstance(item, internal.types.dictionary):
            res = ("{:s}: {:s}".format(cls.repr(k), cls.repr(v)) for k, v in item.items())
            return u"{{{:s}}}".format(', '.join(res))

        return u"{!r}".format(item)

    # On Python2, utf-8 strings are not rendered to a string properly. This
    # screws up the output when trying to write to the console because IDA
    # will then try to utf-8 decode the string manually. To work around this,
    # the following implementation escapes the keys manually, and then utf-8
    # encodes them when concatenating them together. After we have nicely
    # formatted our entire dict, then we re-encode it back to utf-8 for printing.
    if sys.version_info.major < 3:
        @classmethod
        def kwargs(cls, kwds):
            '''Format a dictionary (from kwargs) so that it can be emitted to a user as part of a message.'''
            res = []
            for key, value in kwds.items():
                k, v = cls.escape(key), cls.repr(value)
                res.append("{:s}={!s}".format(*(item.encode('utf8') if isinstance(item, unicode) else item for item in (k, v))))
            return ', '.join(res).decode('utf8')

    # In Python3, IDA doesn't seem to do any utf-8 trickery. So, all we need to
    # do is to escape each key and render it to the string. Then when it gets
    # printed, it should be using the correct characters.
    else:
        @classmethod
        def kwargs(cls, kwds):
            '''Format a dictionary (from kwargs) so that it can be emitted to a user as part of a message.'''
            res = []

            # Escape each key, and repr() each value so that we can emit the keyword
            # parameters for a function call using the same syntax that the user
            # would likely type it.
            for key, value in kwds.items():
                # XXX: we could probably force `key` to a string here, but kwargs should
                #      _never_ have a non-string passed as a parameter name. therefore
                #      we graciously accept any exception that gets raised here.
                res.append("{:s}={!s}".format(cls.escape(key), cls.repr(value)))
            return ', '.join(res)

    @classmethod
    def decorate_arguments(cls, *names):
        '''Given a list of argument names, decode them into unicode strings.'''
        return transform(cls.of, *names)

    @classmethod
    def digits(cls, number, base):
        '''Return the number of characters used to represent the `number` of the specified `base`.'''
        fi = sys.float_info
        mantissa, exponent = fi.mant_dig, fi.max_exp - fi.min_exp
        maxpower2 = mantissa - sys.float_info.dig + math.floor(math.log(exponent, 2))

        # These are combined with the mantissa and so the regular logarithm
        # will likely be just enough to calculate it properly.
        if base in {10}:
            logarithm = math.log10(number or 1)
            return math.trunc(1 + math.floor(logarithm))

        # Otherwise, we check if it's an even number or not in order to determine
        # that we need to use the base-less math.log implementation.
        elif not operator.mod(base, 2):
            logarithm = math.log(number or 1, base)

            # This should only use the exponent field inside a floating point number
            if number < pow(2, maxpower2):
                return math.trunc(1 + math.floor(logarithm))

            # To deal with IEEE754's imprecision, we just use Python to format
            # this number as a hexadecimal string and then use its length to
            # figure out how many digits are needed for the desired base.
            count = len("{:b}".format(number))
            return count * 2 // base

        # We don't support any other bases because the author doesn't feel like
        # spending the time to figure out the correct math for this.
        raise NotImplementedError(base)

    # Convert a string to hexadecimal so that it can be displayed.
    tohex = operator.methodcaller('encode', 'hex') if sys.version_info.major < 3 else operator.methodcaller('hex')

    @classmethod
    def indices(cls, string, characters):
        '''Return a generator that yields each index of the given `characters` found in `string`.'''
        iterable = (string.find(character) for character in characters)
        current, index = 0, min([index for index in iterable if 0 <= index] or [-1])
        while 0 <= index:
            yield current + index
            current, string = current + 1 + index, string[1 + index:]
            iterable = [string.find(character) for character in characters]
            index = min([index for index in iterable if 0 <= index] or [-1])
        return

### wrapping functions with another caller whilst preserving the wrapped function
class wrap(object):
    """
    A lot of magic is in this class which allows one to do a proper wrap
    around a single callable.
    """

    import opcode
    if sys.version_info.major < 3:
        import compiler.consts as consts
    else:
        import inspect as consts

    # Assembler for Python2 bytecode, where each opcode is either a single-byte or a tri-byte.
    if sys.version_info.major < 3:
        @classmethod
        def co_assemble(cls, operation, operand=None):
            '''Assembles the specified `operation` and `operand` into a code string.'''
            opcode = cls.opcode.opmap[operation]
            if operand is None:
                return bytes(bytearray([opcode]))

            # if operand was defined, then encode it
            op1 = (operand & 0x00ff) // 0x0001
            op2 = (operand & 0xff00) // 0x0100
            return bytes(bytearray([opcode, op1, op2]))

    # Assembler for Python3 bytecode where each opcode is a uint16_t.
    else:
        @classmethod
        def co_assemble(cls, operation, operand=None):
            '''Assembles the specified `operation` and `operand` into a code string.'''
            opcode, ext = cls.opcode.opmap[operation], cls.opcode.EXTENDED_ARG

            # If our current version of Python supports intrinsics, then the
            # operand might need to be converted from a string to an integer.
            if operation in ({'CALL_INTRINSIC_1', 'CALL_INTRINSIC_2'} & cls.opcode.opmap.keys()) and any(hasattr(cls.opcode, attribute) for attribute in {'_intrinsic_1_descs', '_intrinsic_2_descs'}):
                intrinsic_map = {attribute : descs.index(attribute) for descs, attribute in itertools.chain(*((lambda desc: zip([desc] * len(desc), desc))(getattr(cls.opcode, attribute)) for attribute in {'_intrinsic_1_descs', '_intrinsic_2_descs'} if hasattr(cls.opcode, attribute)))}
                operand = intrinsic_map.get(operand, operand)

            # If the operand fits within a single byte, then pack it and return.
            if (operand or 0) < 0x00000100:
                return bytes(bytearray([opcode, operand or 0]))

            # We clamp the operands' maximum length to 4 bytes (32-bits) because
            # that is the most that python's runtime supports. When calculating
            # the MSB, we have to hack up the math because Python's imprecision
            # has a significant influence on the logarithm result.
            msb = math.ceil(math.log(operand or 1, 2))
            operands = [ 0xff & operand // pow(2, shift) for shift in range(0, min(32, msb), 8) ]

            iterable = itertools.chain(([ext, item] for item in operands[:-1]), ([opcode, item] for item in operands[-1:]))
            return bytes(bytearray(itertools.chain(*iterable)))

    @classmethod
    def co_varargsQ(cls, co):
        '''Returns whether the provided code type, `co`, takes variable arguments.'''
        return bool(pycompat.code.flags(co) & cls.consts.CO_VARARGS)

    @classmethod
    def co_varkeywordsQ(cls, co):
        '''Returns whether the provided code type, `co`, takes variable keyword arguments.'''
        return bool(pycompat.code.flags(co) & cls.consts.CO_VARKEYWORDS)

    @classmethod
    def cell(cls, *args):
        '''Convert `args` into a ``cell`` tuple.'''
        return tuple((pycompat.function.closure((lambda item: lambda : item)(arg))[0]) for arg in args)

    # The following classmethods are responsible for assembling the equivalent
    # of the closure being returned from the following python. The difference is
    # that the number of arguments, types, and their names are being directly
    # copied from the original callable.

    # def wrap(callable, wrapper):
    #     def result(arg1, arg2, arg3, arg4, *args, **kwargs):
    #         return wrapper(callable, arg1, arg2, arg3, arg4, *args, **kwargs)
    #     return result

    # The reason why we're assembling this directly is so that the returned
    # object has the has the _exact_ same arguments (including both wild and
    # keyword arguments) which allows python's auto-documentation to still work
    # exactly the same even thbough it has been decorated.

    @classmethod
    def assemble_2x(cls, function, wrapper, bound=False):
        """Assemble a ``types.CodeType`` that will execute `wrapper` with `F` as its first parameter.

        If `bound` is ``True``, then assume that the first parameter for `F` represents the instance it's bound to.
        """
        F, C, S = (pycompat.function.extract(item) for item in [function, wrapper, cls.assemble_2x])
        Fc, Cc, Sc = (pycompat.function.code(item) for item in [F, C, S])

        ## build the namespaces that we'll use
        Tc = cls.co_varargsQ(Fc), cls.co_varkeywordsQ(Fc)

        # first we'll build the globals that get passed to the wrapper
        Sargs = ('F', 'wrapper')
        Svals = (f if callable(f) else fo for f, fo in [(function, F), (wrapper, C)])

        # rip out the arguments from our target `F`
        varnames, argcount = pycompat.code.varnames(Fc), pycompat.code.argcount(Fc)
        Fargs = varnames[:argcount]
        Fwildargs = varnames[argcount : argcount + sum(Tc)]

        # combine them into tuples for looking up variables
        co_names, co_varnames = Sargs[:], Fargs[:] + Fwildargs[:]

        # free variables (that get passed to `C`)
        co_freevars = Sargs[:2]

        # constants for code type (which consist of just the self-doc)
        co_consts = (pycompat.function.documentation(F),)

        ## figure out some things for assembling the bytecode

        # first we'll grab the call instruction type to use
        call_ = {
            (False, False) : 'CALL_FUNCTION',
            (True, False)  : 'CALL_FUNCTION_VAR' if 'CALL_FUNCTION_VAR' in cls.opcode.opmap else 'CALL_FUNCTION_KW',
            (False, True)  : 'CALL_FUNCTION_KW',
            (True, True)   : 'CALL_FUNCTION_VAR_KW' if 'CALL_FUNCTION_VAR_KW' in cls.opcode.opmap else 'CALL_FUNCTION_EX',
        }
        call = call_[Tc]

        # now we'll determine the flags to apply
        flags_ = {
            (False, False) : 0,
            (True, False)  : pycompat.co_flags.CO_VARARGS,
            (False, True)  : pycompat.co_flags.CO_VARKEYWORDS,
            (True, True)   : pycompat.co_flags.CO_VARARGS | pycompat.co_flags.CO_VARKEYWORDS
        }

        co_flags = pycompat.co_flags.CO_NESTED | pycompat.co_flags.CO_OPTIMIZED | pycompat.co_flags.CO_NEWLOCALS | flags_[Tc]

        ## assemble the code type that gets turned into a function
        code_, co_stacksize = [], 0
        asm = code_.append

        # first we'll dereference our cellvar for `wrapper`
        asm(cls.co_assemble('LOAD_DEREF', co_freevars.index('wrapper')))
        co_stacksize += 1

        # include the original `F` as the first arg
        asm(cls.co_assemble('LOAD_DEREF', co_freevars.index('F')))
        co_stacksize += 1

        # now we can include all of the original arguments (cropped by +1 if bound)
        for n in Fargs[int(bound):]:
            asm(cls.co_assemble('LOAD_FAST', co_varnames.index(n)))
            co_stacksize += 1

        # include any wildcard arguments
        for n in Fwildargs:
            asm(cls.co_assemble('LOAD_FAST', co_varnames.index(n)))
            co_stacksize += 1

        # call `wrapper` with the correct call type (+1 for `F`, -1 if bound)
        asm(cls.co_assemble(call, len(Fargs) + 1 - int(bound)))

        # and then return its value
        asm(cls.co_assemble('RETURN_VALUE'))

        # combine it into a single code string
        co_code = bytes().join(code_)

        ## next we'll construct the code type based on what we have
        cargs = pycompat.code.cons(
            len(Fargs), len(co_names) + len(co_varnames) + len(co_freevars),
            co_stacksize, co_flags, co_code,
            co_consts, co_names, co_varnames,
            Fc.co_filename, Fc.co_name, Fc.co_firstlineno,
            bytes(), co_freevars, ()
        )

        func_code = pycompat.code.new(cargs)

        ## and then turn it back into a function
        res = pycompat.function.new(func_code, pycompat.function.globals(F), pycompat.function.name(F), pycompat.function.defaults(F), cls.cell(*Svals))
        pycompat.function.set_name(res, pycompat.function.name(F))
        pycompat.function.set_documentation(res, pycompat.function.documentation(F))
        setattr(res, '__qualname__', F.__qualname__) if hasattr(F, '__qualname__') else None
        return res

    # The following Py3 implementation is similar to the prior Py2 impementation,
    # except that bytecodes for the parameters being different due to CALL_FUNCTION_EX.

    @classmethod
    def assemble_38x(cls, function, wrapper, bound=False):
        """Assemble a ``types.CodeType`` that will execute `wrapper` with `F` as its first parameter.

        If `bound` is ``True``, then assume that the first parameter for `F` represents the instance it's bound to.
        """
        F, C, S = (pycompat.function.extract(item) for item in [function, wrapper, cls.assemble_38x])
        Fc, Cc, Sc = (pycompat.function.code(item) for item in [F, C, S])
        Nvarargs, Nvarkwds = 1 if cls.co_varargsQ(Fc) else 0, 1 if cls.co_varkeywordsQ(Fc) else 0

        ### build the namespaces that we'll use.

        # first we'll build the externals that get passed to the wrapper.
        Sargs = ('F', 'wrapper')
        Svals = (f if callable(f) else fo for f, fo in [(function, F), (wrapper, C)])

        # rip out the arguments from our target `F`.
        varnames, argcount = pycompat.code.varnames(Fc), pycompat.code.argcount(Fc)
        Fargs, Fdefaults = varnames[:argcount], pycompat.function.defaults(F)
        Fvarargs, Fvarkwds = varnames[argcount : argcount + Nvarargs], varnames[argcount + Nvarargs : argcount + Nvarargs + Nvarkwds]

        # combine them into tuples for looking up variables.
        co_names, co_varnames = Sargs[:], Fargs[:] + Fvarargs[:] + Fvarkwds[:]

        ## free variables (that get passed to `C`).
        co_freevars = Sargs[:2]

        ## constants for code type (which consist of just the self-doc).
        co_consts = (pycompat.function.documentation(F),)

        ## flags for the code type.
        co_flags = pycompat.co_flags.CO_NESTED | pycompat.co_flags.CO_OPTIMIZED | pycompat.co_flags.CO_NEWLOCALS
        co_flags |= pycompat.co_flags.CO_VARARGS if Nvarargs > 0 else 0
        co_flags |= pycompat.co_flags.CO_VARKEYWORDS if Nvarkwds > 0 else 0

        ### figure out some things for assembling the bytecode.
        code_, co_stacksize = [], 0
        asm = code_.append

        # first we push the callable that we need to call to wrap our function.
        asm(cls.co_assemble('LOAD_DEREF', co_freevars.index('wrapper')))
        co_stacksize += 1

        ## now we need to pack all of our parameters into a tuple starting with our
        ## `F` parameter which contains the function taht's being wrapped.
        asm(cls.co_assemble('LOAD_DEREF', co_freevars.index('F')))
        co_stacksize += 1

        # now we can include all of the original arguments (cropped by +1 if bound).
        for item in Fargs[int(bound):]:
            asm(cls.co_assemble('LOAD_FAST', co_varnames.index(item)))
            co_stacksize += 1

        # then we can finally pack it into a tuple
        asm(cls.co_assemble('BUILD_TUPLE', 1 + len(Fargs[int(bound):])))        # pack(F, args...)

        ## now we need to pack all wildcard arguments...
        for item in Fvarargs:
            asm(cls.co_assemble('LOAD_FAST', co_varnames.index(item)))
        co_stacksize = max(2 + len(Fvarargs), co_stacksize)                     # len(varags) + build_tuple + wrapper

        # ...into this unpack-with-call tuple.
        asm(cls.co_assemble('BUILD_TUPLE_UNPACK_WITH_CALL', 1 + len(Fvarargs))) # pack(pack(F, args...), varargs)

        ## now we need to pack all kw arguments...
        for item in Fvarkwds:
            asm(cls.co_assemble('LOAD_FAST', co_varnames.index(item)))
        co_stacksize = max(2 + len(Fvarkwds), co_stacksize)                     # len(varkwds) + build_tuple_unpack + wrapper

        # ...into this unpack-with-call map.
        asm(cls.co_assemble('BUILD_MAP_UNPACK_WITH_CALL', len(Fvarkwds)))       # pack(pack(F, args..., varargs), kwargs)

        ## finally we have our arguments, and can now assemble our call...
        asm(cls.co_assemble('CALL_FUNCTION_EX', 1))

        # ...and then return its value.
        asm(cls.co_assemble('RETURN_VALUE'))

        ## next we'll construct the code type using our new opcodes.

        # combine our opcodes into a single code string.
        co_code = bytes().join(code_)

        # consruct the new code object with all our fields.
        cargs = pycompat.code.cons(
            len(Fargs), len(co_names) + len(co_varnames) + len(co_freevars),
            co_stacksize, co_flags, co_code,
            co_consts, co_names, co_varnames,
            Fc.co_filename, Fc.co_name, Fc.co_firstlineno,
            bytes(), co_freevars, ()
        )

        func_code = pycompat.code.new(cargs)

        ## finally take our code object, and put it back into a function/callable.
        res = pycompat.function.new(func_code, pycompat.function.globals(F), pycompat.function.name(F), pycompat.function.defaults(F), cls.cell(*Svals))
        pycompat.function.set_name(res, pycompat.function.name(F))
        pycompat.function.set_documentation(res, pycompat.function.documentation(F))
        setattr(res, '__qualname__', F.__qualname__) if hasattr(F, '__qualname__') else None
        return res

    # The following Py3 implementation is pretty similar to the prior one, but since the
    # BUILD_XXX_UNPACK_WITH_CALL opcodes don't exist..we end up using the BUILD_LIST with
    # LIST_TO_TUPLE and BUILD_MAP with DICT_MERGE to prepare CALL_FUNCTION_EX's parameters.

    @classmethod
    def assemble_39x(cls, function, wrapper, bound=False):
        """Assemble a ``types.CodeType`` that will execute `wrapper` with `F` as its first parameter.

        If `bound` is ``True``, then assume that the first parameter for `F` represents the instance it's bound to.
        """
        F, C, S = (pycompat.function.extract(item) for item in [function, wrapper, cls.assemble_39x])
        Fc, Cc, Sc = (pycompat.function.code(item) for item in [F, C, S])
        Nvarargs, Nvarkwds = 1 if cls.co_varargsQ(Fc) else 0, 1 if cls.co_varkeywordsQ(Fc) else 0

        ### build the namespaces that we'll use.

        # first we'll build the externals that get passed to the wrapper.
        Sargs = ('F', 'wrapper')
        Svals = (f if callable(f) else fo for f, fo in [(function, F), (wrapper, C)])

        # rip out the arguments from our target `F`.
        varnames, argcount = pycompat.code.varnames(Fc), pycompat.code.argcount(Fc)
        Fargs, Fdefaults = varnames[:argcount], pycompat.function.defaults(F)
        Fvarargs, Fvarkwds = varnames[argcount : argcount + Nvarargs], varnames[argcount + Nvarargs : argcount + Nvarargs + Nvarkwds]

        # combine them into tuples for looking up variables.
        co_names, co_varnames = Sargs[:], Fargs[:] + Fvarargs[:] + Fvarkwds[:]

        ## free variables (that get passed to `C`).
        co_freevars = Sargs[:2]

        ## constants for code type (which consist of just the self-doc).
        co_consts = (pycompat.function.documentation(F),)

        ## flags for the code type.
        co_flags = pycompat.co_flags.CO_NESTED | pycompat.co_flags.CO_OPTIMIZED | pycompat.co_flags.CO_NEWLOCALS
        co_flags |= pycompat.co_flags.CO_VARARGS if Nvarargs > 0 else 0
        co_flags |= pycompat.co_flags.CO_VARKEYWORDS if Nvarkwds > 0 else 0

        ### figure out some things for assembling the bytecode.
        code_, co_stacksize = [], 0
        asm = code_.append

        # first we push the callable that we need to call to wrap our function.
        asm(cls.co_assemble('LOAD_DEREF', co_freevars.index('wrapper')))
        co_stacksize += 1

        ## now we need to pack all of our parameters into a tuple starting with our
        ## `F` parameter which contains the function that's being wrapped.
        asm(cls.co_assemble('LOAD_DEREF', co_freevars.index('F')))
        co_stacksize += 1

        # now we can include all of the original arguments (cropped by +1 if bound).
        for item in Fargs[int(bound):]:
            asm(cls.co_assemble('LOAD_FAST', co_varnames.index(item)))
            co_stacksize += 1

        # then we can finally pack it into a list
        asm(cls.co_assemble('BUILD_LIST', 1 + len(Fargs[int(bound):])))         # pack(F, args)

        ## now we need to pack all wildcard arguments...
        for item in Fvarargs:
            asm(cls.co_assemble('LOAD_FAST', co_varnames.index(item)))
            asm(cls.co_assemble('LIST_EXTEND', 1))
        co_stacksize = max(2 + len(Fvarargs), co_stacksize)                     # wrapper + pack(F, args) + load_fast(varargs)

        # ...and convert it into a tuple
        asm(cls.co_assemble('LIST_TO_TUPLE'))

        ## now we need to pack all kw arguments...
        asm(cls.co_assemble('BUILD_MAP', 0))

        for item in Fvarkwds:
            asm(cls.co_assemble('LOAD_FAST', co_varnames.index(item)))
            asm(cls.co_assemble('DICT_MERGE', 1))
        co_stacksize = max(2 + len(Fvarkwds), co_stacksize)                     # wrapper + pack(F, args, varargs) + load_fast(varkwds)

        ## finally we have our arguments, and can now assemble our call...
        asm(cls.co_assemble('CALL_FUNCTION_EX', 1))

        # ...and then return its value.
        asm(cls.co_assemble('RETURN_VALUE'))

        ## next we'll construct the code type using our new opcodes.

        # combine our opcodes into a single code string.
        co_code = bytes().join(code_)

        # construct the new code object with all our fields.
        cargs = pycompat.code.cons(
            len(Fargs), len(co_names) + len(co_varnames) + len(co_freevars),
            co_stacksize, co_flags, co_code,
            co_consts, co_names, co_varnames,
            Fc.co_filename, Fc.co_name, Fc.co_firstlineno,
            bytes(), co_freevars, ()
        )

        func_code = pycompat.code.new(cargs)

        ## finally take our code object, and put it back into a function/callable.
        res = pycompat.function.new(func_code, pycompat.function.globals(F), pycompat.function.name(F), pycompat.function.defaults(F), cls.cell(*Svals))
        pycompat.function.set_name(res, pycompat.function.name(F))
        pycompat.function.set_documentation(res, pycompat.function.documentation(F))
        setattr(res, '__qualname__', F.__qualname__) if hasattr(F, '__qualname__') else None
        return res

    # The following Py3 implementation is different from the previous one due to Py311 lining
    # up the freevars and cellvars with the varnames. This results in LOAD_DEREF using an index
    # relative to varnames to access a freevar from the captured function along with the need to
    # calculate the number of locals differently. It also seems like there's some more crap we
    # can shove in the prologue that could allow Py311 to optimize it (lol). Also.. this pasta
    # definitely seems like it's nearing its ripeness.

    @classmethod
    def assemble_312x(cls, function, wrapper, bound=False):
        """Assemble a ``types.CodeType`` that will execute `wrapper` with `F` as its first parameter.

        If `bound` is ``True``, then assume that the first parameter for `F` represents the instance it's bound to.
        """
        F, C, S = (pycompat.function.extract(item) for item in [function, wrapper, cls.assemble_39x])
        Fc, Cc, Sc = (pycompat.function.code(item) for item in [F, C, S])
        Nvarargs, Nvarkwds = 1 if cls.co_varargsQ(Fc) else 0, 1 if cls.co_varkeywordsQ(Fc) else 0

        ### build the namespaces that we'll use.

        # first we'll build the externals that get passed to the wrapper.
        Sargs = ('F', 'wrapper')
        Svals = (f if callable(f) else fo for f, fo in [(function, F), (wrapper, C)])

        # rip out the arguments from our target `F`.
        varnames, argcount = pycompat.code.varnames(Fc), pycompat.code.argcount(Fc)
        Fargs, Fdefaults = varnames[:argcount], pycompat.function.defaults(F)
        Fvarargs, Fvarkwds = varnames[argcount : argcount + Nvarargs], varnames[argcount + Nvarargs : argcount + Nvarargs + Nvarkwds]

        # combine them into tuples for looking up variables.
        co_names, co_varnames = Sargs[:], Fargs[:] + Fvarargs[:] + Fvarkwds[:]

        ## free variables (that get passed to `C`).
        co_freevars = Sargs[:2]

        ## constants for code type (which consist of just the self-doc).
        co_consts = (pycompat.function.documentation(F),)

        ## flags for the code type.
        co_flags = pycompat.co_flags.CO_NESTED | pycompat.co_flags.CO_OPTIMIZED | pycompat.co_flags.CO_NEWLOCALS
        co_flags |= pycompat.co_flags.CO_VARARGS if Nvarargs > 0 else 0
        co_flags |= pycompat.co_flags.CO_VARKEYWORDS if Nvarkwds > 0 else 0

        ### figure out some things for assembling the bytecode.
        code_, co_stacksize = [], 0
        asm = code_.append

        # push the equivalence of the prologue, which copies free variables
        # from our closure and warms up Py11's predictor (lol).
        asm(cls.co_assemble('COPY_FREE_VARS', len(co_freevars)))
        asm(cls.co_assemble('RESUME', 0))

        # then we push the callable that we need to call to wrap our function.
        if sys.version_info.minor < 13:
            asm(cls.co_assemble('PUSH_NULL', 0))
            asm(cls.co_assemble('LOAD_DEREF', len(co_varnames) + co_freevars.index('wrapper')))
            co_stacksize += 1

        # python 3.13 seems to swap the order of these. i'm not sure why, but it
        # seems to prevent it from crashing. so, we do as we're fucking told.
        else:
            asm(cls.co_assemble('LOAD_DEREF', len(co_varnames) + co_freevars.index('wrapper')))
            asm(cls.co_assemble('PUSH_NULL', 0))
            co_stacksize += 1

        ## now we need to pack all of our parameters into a tuple starting with our
        ## `F` parameter which contains the function that's being wrapped.
        asm(cls.co_assemble('LOAD_DEREF', len(co_varnames) + co_freevars.index('F')))
        co_stacksize += 1

        # now we can include all of the original arguments (cropped by +1 if bound).
        for item in Fargs[int(bound):]:
            asm(cls.co_assemble('LOAD_FAST', co_varnames.index(item)))
            co_stacksize += 1

        # then we can finally pack it into a list
        asm(cls.co_assemble('BUILD_LIST', 1 + len(Fargs[int(bound):])))         # pack(F, args)

        ## now we need to pack all wildcard arguments...
        for item in Fvarargs:
            asm(cls.co_assemble('LOAD_FAST', co_varnames.index(item)))
            asm(cls.co_assemble('LIST_EXTEND', 1))
        co_stacksize = max(2 + len(Fvarargs), co_stacksize)                     # wrapper + pack(F, args) + load_fast(varargs)

        # ...and convert it into a tuple. if we're using 3.12, though,
        # then the list_to_tuple opcode has been changed to an intrinsic.
        if sys.version_info.minor < 12:
            asm(cls.co_assemble('LIST_TO_TUPLE'))
        else:
            asm(cls.co_assemble('CALL_INTRINSIC_1', 'INTRINSIC_LIST_TO_TUPLE'))

        ## now we need to pack all kw arguments...
        asm(cls.co_assemble('BUILD_MAP', 0))

        for item in Fvarkwds:
            asm(cls.co_assemble('LOAD_FAST', co_varnames.index(item)))
            asm(cls.co_assemble('DICT_MERGE', 1))
        co_stacksize = max(2 + len(Fvarkwds), co_stacksize)                     # wrapper + pack(F, args, varargs) + load_fast(varkwds)

        ## finally we have our arguments, and can now assemble our call...
        asm(cls.co_assemble('CALL_FUNCTION_EX', 1))

        # ...and then return its value.
        asm(cls.co_assemble('RETURN_VALUE'))

        ## next we'll construct the code type using our new opcodes.

        # combine our opcodes into a single code string.
        co_code = bytes().join(code_)

        # construct the new code object with all our fields.
        cargs = pycompat.code.cons(
            len(Fargs), len(co_varnames),
            co_stacksize, co_flags, co_code,
            co_consts, co_names, co_varnames,
            Fc.co_filename, Fc.co_name, Fc.co_firstlineno,
            bytes(), co_freevars, ()
        )

        func_code = pycompat.code.new(cargs)

        ## finally take our code object, and put it back into a function/callable.
        res = pycompat.function.new(func_code, pycompat.function.globals(F), pycompat.function.name(F), pycompat.function.defaults(F), cls.cell(*Svals))
        pycompat.function.set_name(res, pycompat.function.name(F))
        pycompat.function.set_documentation(res, pycompat.function.documentation(F))
        setattr(res, '__qualname__', F.__qualname__) if hasattr(F, '__qualname__') else None
        return res

    def __new__(cls, callable, wrapper):
        '''Return a function similar to `callable` that calls `wrapper` with `callable` as the first argument.'''
        cons, f = pycompat.function.constructor(callable), pycompat.function.extract(callable)
        Fassemble = cls.assemble_2x if sys.version_info.major < 3 else cls.assemble_38x if sys.version_info.minor < 9 else cls.assemble_39x if sys.version_info.minor < 11 else cls.assemble_312x

        # figure out the bytecode to use depending on the python version.
        if sys.version_info.major < 3:
            Fassemble = cls.assemble_2x
        elif sys.version_info.minor < 9:
            Fassemble = cls.assemble_38x
        elif sys.version_info.minor < 11:
            Fassemble = cls.assemble_39x
        else:
            Fassemble = cls.assemble_312x

        # create a wrapper for the function that'll execute `callable` with the function as its first argument, and the rest with any args
        res = Fassemble(callable, wrapper, bound=isinstance(callable, (internal.types.classmethod, internal.types.method)))
        res.__module__ = getattr(callable, '__module__', getattr(callable, '__module__', '__main__'))

        # now we re-construct it and then return it
        return cons(res)

### function decorator for translating arguments belonging to a function
def transform(translate, *names):
    '''This applies the callable `translate` to any function arguments that match `names` in the decorated function.'''
    names = {name for name in names}
    def wrapper(F, *rargs, **rkwds):
        f = pycompat.function.extract(F)
        argnames, defaults, (wildname, _) = pycompat.function.arguments(f)

        # convert any positional arguments
        res = []
        for value, argname in zip(rargs, argnames):
            try:
                res.append(translate(value) if argname in names else value)
            except Exception as E:
                cls = E.__class__
                raise cls("{!s}: Exception raised while transforming parameter `{:s}` with value {!r}".format('.'.join([f.__module__, f.__name__]), argname, value))

        # get the rest
        for value in rargs[len(res):]:
            try:
                res.append(translate(value) if wildname in names else value)
            except Exception as E:
                cls = E.__class__
                raise cls("{!s}: Exception raised while transforming parameters `{:s}` with value {!r}".format('.'.join([f.__module__, f.__name__]), wildname, value))

        # convert any keywords arguments
        kwds = {k : v for k, v in rkwds.items()}
        for argname in {item for item in rkwds.keys()} & names:
            try:
                kwds[argname] = translate(kwds[argname])
            except Exception as E:
                cls = E.__class__
                raise cls("{!s}: Exception raised while transforming parameter `{:s}` with value {!r}".format('.'.join([f.__module__, f.__name__]), argname, kwds[argname]))
        return F(*res, **kwds)

    # decorater that wraps the function `F` with `wrapper`.
    def result(F):
        return wrap(F, wrapper)
    return result

def require_attribute(object, attribute):
    """A function decorator that avoids defining the target function unless the given `object` has the specified `attribute`.

    This decorator returns the symbol with the previous name of the decorated
    target if one was found, or `None` if neither was found.
    """
    def ignored(wrapped):
        func = pycompat.function.extract(wrapped)
        name = pycompat.function.name(func)
        if name in sys._getframe().f_back.f_locals:
            return sys._getframe().f_back.f_locals[name]
        return
    def available(wrapped):
        return wrapped
    return available if hasattr(object, attribute) else ignored

def get_array_typecode(size, *default):
    '''Return the correct integer typecode for the given size.'''
    if hasattr(get_array_typecode, 'lookup'):
        L = getattr(get_array_typecode, 'lookup')
        return L.get(size, L.get(*default)) if default else L[size]

    # wow, wtf python...
    dword = 'L' if len(array.array('I', 4 * b'\0')) > 1 else 'I'
    qword = 'Q' if len(array.array('L', 8 * b'\0')) > 1 else 'L'

    # assign out lookup dictionary
    get_array_typecode.lookup = {
        1 : 'B',
        2 : 'H',
        4 : dword,
        8 : qword,
    }
    return get_array_typecode(size, *default)

def float_of_integer(integer, mantissa_bits, exponent_bits, sign_bits):
    """Decode the specified `integer` using the sizes provided for `mantissa_bits`, `exponent_bits`, and `sign_bits`.

    Each of the sizes are to be provided as the number of bits used to represent that component.
    """

    # Use the number of bits for each of our components to calculate the
    # total number of bits.
    fraction_bits, exponent_bits, sign_bits = mantissa_bits, exponent_bits, sign_bits
    components = [fraction_bits, exponent_bits, sign_bits]
    size = math.trunc(math.ceil(sum(components) / 8))

    # This way we can use them to build an array of the shift to get to
    # each individual position.
    position, shifts = 0, []
    for cb in components:
        shifts.append(position)
        position += cb

    # Validate the sizes match.
    if position != sum(components):
        raise ValueError("The total number of bits for the components ({:d}) does not correspond to the size ({:d}) of the integer.".format(sum(components), 8 * size))

    # Build the masks we will use to compose a floating-point number
    fraction_shift, exponent_shift, sign_shift = (pow(2, item) for item in shifts)
    bias = pow(2, exponent_bits) // 2 - 1

    fraction_mask = fraction_shift * (pow(2, fraction_bits) - 1)
    exponent_mask = exponent_shift * (pow(2, exponent_bits) - 1)
    sign_mask = sign_shift * (pow(2, sign_bits) - 1)

    # Now to decode our components...
    mantissa = (integer & fraction_mask) // fraction_shift
    exponent = (integer & exponent_mask) // exponent_shift
    sign = (integer & sign_mask) // sign_shift

    # ...and then convert it into a float
    if exponent > 0 and exponent < pow(2, exponent_bits) - 1:
        s = -1 if sign else +1
        e = exponent - bias
        m = 1.0 + float(mantissa) / pow(2, fraction_bits)
        return math.ldexp(math.copysign(m, s), e)

    # Check if we need to return any special constants
    if exponent == pow(2, exponent_bits) - 1 and mantissa == 0:
        return float('-inf') if sign else float('+inf')
    elif exponent in {0, pow(2, fraction_bits) - 1} and mantissa != 0:
        return float('-nan') if sign else float('+nan')
    elif exponent == 0 and mantissa == 0:
        return float('-0') if sign else float('+0')

    # Raise an exception as we weren't able to decode the semantics for
    # each component.
    raise ValueError("Unable to decode integer ({:#x}) using the values extracted for the mantissa ({:#x}), exponent ({:#x}), and sign flag ({:d}).".format(integer, mantissa, exponent, sign))

def float_to_integer(float, mantissa_bits, exponent_bits, sign_bits):
    """Encode the specified `float` using the sizes provided for `mantissa_bits`, `exponent_bits`, and `sign_bits`.

    Each of the sizes are to be provided as the number of bits used to represent that component.
    """
    exponentbias = pow(2, exponent_bits) // 2 - 1

    # Figure out what type of floating-point number this is
    if math.isnan(float):
        sign, exponent, mantissa = 0, pow(2, exponent_bits) - 1, ~0
    elif math.isinf(float):
        sign, exponent, mantissa = 1 if float < 0 else 0, pow(2, exponent_bits) - 1, 0
    elif float == 0.0 and math.atan2(float, float) < 0.0:
        sign, exponent, mantissa = 1, 0, 0
    elif float == 0.0 and math.atan2(float, float) == 0.0:
        sign, exponent, mantissa = 0, 0, 0
    else:
        # First extract the exponent and the mantissa
        m, e = math.frexp(float)

        # Now we need to copy out the sign flag
        sign = 1 if math.copysign(1.0, m) < 0 else 0

        # Adjust the exponent so that we can remove the implicit bit
        exponent = e + exponentbias - 1
        m = abs(m) * 2.0 - 1.0 if exponent else abs(m)

        # Finally we need to convert the fractional mantissa into an integer
        mantissa = math.trunc(m * pow(2, mantissa_bits))

    # Calculate the shift and mask for each component of the encoded float
    components = [mantissa_bits, exponent_bits, sign_bits]
    position, shifts = 0, []
    for cb in components:
        shifts.append(position)
        position += cb
    mantissa_shift, exponent_shift, sign_shift = (pow(2, item) for item in shifts)
    mantissa_mask, exponent_mask, sign_mask = (pow(2, item) - 1 for item in components)

    # Now to store each component into an integer that we can return
    res = 0
    res += (sign & sign_mask) * sign_shift
    res += (exponent & exponent_mask) * exponent_shift
    res += (mantissa & mantissa_mask) * mantissa_shift
    return res
