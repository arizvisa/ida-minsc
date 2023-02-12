"""
Utilities module (internal)

This module contains a number of tools that help with the interface for this
plugin. This contains things such as the multicase decorator, the matcher
class for querying and filtering lists of things, support for aliasing
functions, and a number of functional programming primitives (combinators).
"""

import six, builtins

import os, logging, types, weakref
import functools, operator, itertools
import sys, heapq, collections, array, math

import internal
import idaapi

__all__ = ['fpack','funpack','fcar','fcdr','finstance','fhasitem','fitemQ','fgetitem','fitem','fsetitem','fdelitem','fhasattr','fattributeQ','fgetattr','fattribute','fsetattr','fsetattribute','fconstant','fdefault','fidentity','first','second','third','last','fcompose','fdiscard','fcondition','fmap','flazy','fpartial','fapply','fcurry','frpartial','freverse','fcatch','fcomplement','fnot','ilist','liter','ituple','titer','itake','iget','islice','imap','ifilter','ichain','izip','lslice','lmap','lfilter','lzip','count']

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
finstance = lambda *type: frpartial(builtins.isinstance, type)
# return a closure that will check if its argument has an item `key`.
fhasitem = fitemQ = lambda key: frpartial(operator.contains, key)
# return a closure that will get a particular element from an object.
fgetitem = fitem = lambda item, *default: lambda object: default[0] if default and item not in object else object[item]
# return a closure that will set a particular element on an object.
fsetitem = lambda item: lambda value: lambda object: operator.setitem(object, item, value) or object
# return a closure that will remove a particular element from an object and return the modified object
fdelitem = lambda *items: fcompose(fmap(fidentity, *[fcondition(fhasitem(item))(frpartial(operator.delitem, item), None) for item in items]), builtins.iter, builtins.next)
# return a closure that will check if its argument has an `attribute`.
fhasattr = fattributeQ = lambda attribute: frpartial(builtins.hasattr, attribute)
# return a closure that will get a particular attribute from an object.
fgetattr = fattribute = lambda attribute, *default: lambda object: getattr(object, attribute, *default)
# return a closure that will set a particular attribute on an object.
fsetattr = fsetattribute = lambda attribute: lambda value: lambda object: builtins.setattr(object, attribute, value) or object
# return a closure that always returns `object`.
fconstant = fconst = falways = lambda object: lambda *a, **k: object
# a closure that returns its argument always.
fidentity = lambda object: object
# a closure that returns a default value if its object is false-y
fdefault = lambda default: lambda object: object or default
# return the first, second, or third item of a box.
first, second, third, last = operator.itemgetter(0), operator.itemgetter(1), operator.itemgetter(2), operator.itemgetter(-1)
# return a closure that executes a list of functions one after another from left-to-right.
fcompose = lambda *Fa: functools.reduce(lambda F1, F2: lambda *a: F1(F2(*a)), builtins.reversed(Fa))
# return a closure that executes function `F` whilst discarding any arguments passed to it.
fdiscard = lambda F, *a, **k: lambda *ap, **kp: F(*a, **k)
# return a closure that executes function `crit` and then returns/executes `f` or `t` based on whether or not it's successful.
fcondition = lambda crit: lambda t, f: \
    lambda *a, **k: (t(*a, **k) if builtins.callable(t) else t) if crit(*a, **k) else (f(*a, **k) if builtins.callable(f) else f)
# return a closure that takes a list of functions to execute with the provided arguments
fmap = lambda *Fa: lambda *a, **k: builtins.tuple(F(*a, **k) for F in Fa)
#lazy = lambda F, state={}: lambda *a, **k: state[(F, a, builtins.tuple(builtins.sorted(k.items())))] if (F, a, builtins.tuple(builtins.sorted(k.items()))) in state else state.setdefault((F, a, builtins.tuple(builtins.sorted(k.items()))), F(*a, **k))
#lazy = lambda F, *a, **k: lambda *ap, **kp: F(*(a + ap), **{ key : value for key, value in itertools.chain(k.items(), kp.items())})
# return a memoized closure that's lazy and only executes when evaluated
def flazy(F, *a, **k):
    sortedtuple, state = fcompose(builtins.sorted, builtins.tuple), {}
    def lazy(*ap, **kp):
        A, K = a + ap, sortedtuple(builtins.tuple(k.items()) + builtins.tuple(kp.items()))
        return state[(A, K)] if (A, K) in state else state.setdefault((A, K), F(*A, **{ key : value for key, value in itertools.chain(k.items(), kp.items()) }))
    return lazy
# return a closure with the function's arglist partially applied
fpartial = functools.partial
# return a closure that applies the provided arguments to the function `F`.
fapply = lambda F, *a, **k: lambda *ap, **kp: F(*(a + ap), **{ key : value for key, value in itertools.chain(k.items(), kp.items()) })
# return a closure that will use the specified arguments to call the provided function.
fcurry = lambda *a, **k: lambda F, *ap, **kp: F(*(a + ap), **{ key : value for key, value in itertools.chain(k.items(), kp.items()) })
# return a closure that applies the initial arglist to the end of function `F`.
frpartial = lambda F, *a, **k: lambda *ap, **kp: F(*(ap + builtins.tuple(builtins.reversed(a))), **{ key : value for key, value in itertools.chain(k.items(), kp.items()) })
# return a closure that applies the arglist to function `F` in reverse.
freverse = lambda F, *a, **k: lambda *ap, **kp: F(*builtins.reversed(a + ap), **{ key : value for key, value in itertools.chain(k.items(), kp.items()) })
# return a closure that executes function `F` and includes the caught exception (or None) as the first element in the boxed result.
def fcatch(F, *a, **k):
    def fcatch(*a, **k):
        try: return None, F(*a, **k)
        except: return sys.exc_info()[1], None
    return functools.partial(fcatch, *a, **k)
# boolean inversion of the result of a function
fcomplement = fnot = frpartial(fcompose, operator.not_)
# converts a list to an iterator, or an iterator to a list
ilist, liter = fcompose(builtins.iter, builtins.list), fcompose(builtins.list, builtins.iter)
# converts a tuple to an iterator, or an iterator to a tuple
ituple, titer = fcompose(builtins.iter, builtins.tuple), fcompose(builtins.tuple, builtins.iter)
# take `count` number of elements from an iterator
itake = lambda count: fcompose(builtins.iter, fmap(*[builtins.next] * count), builtins.tuple)
# get the `nth` element from an iterator
iget = lambda count: fcompose(builtins.iter, fmap(*[builtins.next] * count), builtins.tuple, operator.itemgetter(-1))
# copy from itertools
islice, imap, ifilter, ichain, izip = itertools.islice, fcompose(builtins.map, builtins.iter), fcompose(builtins.filter, builtins.iter), itertools.chain, fcompose(builtins.zip, builtins.iter)
# restoration of the Py2-compatible list types
lslice, lmap, lfilter, lzip = fcompose(itertools.islice, builtins.list), fcompose(builtins.map, builtins.list), fcompose(builtins.filter, builtins.list), fcompose(builtins.zip, builtins.list)
# count number of elements of a container
count = fcompose(builtins.iter, builtins.list, builtins.len)

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
            if isinstance(item, (builtins.list, builtins.tuple, builtins.set)):
                for item in item:
                    items |= {item.__name__}
                continue
            items |= {item.__name__}
        return sorted(items)
    def __repr__(self):
        return "{:s}({:s})".format('Pattern', '|'.join(self.__types__()))

### compatibility namespace
class pycompat(object):
    class function_2x(object):
        @classmethod
        def new(cls, code, globals, name, argdefs, closure):
            return types.FunctionType(code, globals, name, argdefs, closure)

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
            return types.CodeType(*attributes)

    class code_37(code_2x):
        @classmethod
        def unpack_extra(cls, object):
            return object.co_kwonlyargcount,
        @classmethod
        def new(cls, attributes, extra=(0,)):
            argcount, nlocals, stacksize, flags, code, consts, names, varnames,filename, name, firstlineno, lnotab, freevars, cellvars = attributes
            kwonlyargcount, = extra
            return types.CodeType(argcount, kwonlyargcount, nlocals, stacksize, flags, code, consts, names, varnames, filename, name, firstlineno, lnotab, freevars, cellvars)

    class code_38(code_2x):
        @classmethod
        def unpack_extra(cls, object):
            return object.co_posonlyargcount, object.co_kwonlyargcount
        @classmethod
        def new(cls, attributes, extra=(0, 0)):
            argcount, nlocals, stacksize, flags, code, consts, names, varnames,filename, name, firstlineno, lnotab, freevars, cellvars = attributes
            posonlyargcount, kwonlyargcount = extra
            return types.CodeType(argcount, posonlyargcount, kwonlyargcount, nlocals, stacksize, flags, code, consts, names, varnames, filename, name, firstlineno, lnotab, freevars, cellvars)

    class code_311(code_2x):
        @classmethod
        def unpack_extra(cls, object):
            return object.co_posonlyargcount, object.co_kwonlyargcount, object.co_qualname, object.co_exceptiontable
        @classmethod
        def new(cls, attributes, extra=(0, 0, str(), bytes())):
            argcount, nlocals, stacksize, flags, code, consts, names, varnames,filename, name, firstlineno, lnotab, freevars, cellvars = attributes
            posonlyargcount, kwonlyargcount, qualname, exceptiontable = extra
            return types.CodeType(argcount, posonlyargcount, kwonlyargcount, nlocals, stacksize, flags, code, consts, names, varnames, filename, name, qualname or name, firstlineno, lnotab, exceptiontable, freevars, cellvars)

    code = code_2x if sys.version_info.major < 3 else code_37 if (sys.version_info.major, sys.version_info.minor) < (3, 8) else code_38 if (sys.version_info.major, sys.version_info.minor) < (3, 11) else code_311

    class method_2x(object):
        @classmethod
        def new(cls, function, instance, type):
            return types.MethodType(function, instance, type)

        @classmethod
        def self(cls, object):
            return object.im_self

        @classmethod
        def type(cls, object):
            return object.im_class

        @classmethod
        def function(cls, object):
            return object.im_func

    class method_3x(object):
        @classmethod
        def new(cls, function, instance, type=None):
            return types.MethodType(function, instance)

        @classmethod
        def self(cls, object):
            return object.__self__

        @classmethod
        def type(cls, object):
            return object.__self__.__class__

        @classmethod
        def function(cls, object):
            return object.__func__

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

    def __new__(cls, *other, **t_args):
        '''Decorate a case of a function with the specified types.'''
        def result(wrapped):

            # First we need to extract the function from whatever type it is
            # so that we can read any properties we need from it. We also extract
            # its "constructor" so that we can re-create it after we've processed it.
            cons, func = cls.reconstructor(wrapped), cls.ex_function(wrapped)

            # Next we need to extract all of the argument information from it. We
            # also need to determine whether it's a special type of some sort so
            # that we know that its first argument is irrelevant to our needs. We
            # also check to see if it's using the magic name "__new__" which takes
            # an implicit parameter that gets passed to it.
            args, defaults, (star, starstar) = cls.ex_args(func)
            s_args = 1 if isinstance(wrapped, (classmethod, types.MethodType)) or func.__name__ in {'__new__'} else 0

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
            res = ok and cls.ex_function(prev)
            if ok and hasattr(res, cls.cache_name):
                cache = getattr(res, cls.cache_name)

            # Otherwise, we simply need to create a new cache entirely.
            else:
                cache = []
                res = cls.new_wrapper(func, cache)
                res.__module__ = getattr(wrapped, '__module__', getattr(func, '__module__', '__main__'))

            # We calculate the priority of this case by trying to match against the
            # most complex definition first.
            argtuple = s_args, args, defaults, (star, starstar)
            priority = len(args) - s_args - len(t_args) + (len(args) and (next((float(i) for i, a in enumerate(args[s_args:]) if a in t_args), 0) / len(args))) + sum(0.3 for item in [star, starstar] if item)

            # Iterate through our cache whilst checking to see if our decorated
            # function is already inside of it.
            current = tuple(t_args.get(_, None) for _ in args), (star, starstar)
            for i, (p, (_, t, a)) in enumerate(cache):
                if p != priority: continue

                # Verify that the function actually matches our current entry. If
                # it does, then we can update the entry and its documentation.
                if current == (tuple(t.get(_, None) for _ in a[1]), a[3]):
                    cache[i] = priority_tuple(priority, (func, t_args, argtuple))
                    res.__doc__ = cls.document(func.__name__, [item for _, item in cache])
                    return cons(res)
                continue

            # That means we should be good to go, so it should be okay to push
            # our new entry into our heap that will be searched upon using the function.
            heapq.heappush(cache, priority_tuple(priority, (func, t_args, argtuple)))
            #heapq.heappush(cache, (priority, (func, t_args, argtuple)))

            # Completely regenerate the documentation using what we have in the cache.
            res.__doc__ = cls.document(func.__name__, [item for _, item in cache])

            # ..and then we can restore the original wrapper in all of its former glory.
            return cons(res)

        # Validate the types of all of our arguments and raise an exception if it used
        # an unsupported type.
        for name, type in t_args.items():
            if not isinstance(type, (builtins.type, builtins.tuple)) and type not in {callable}:
                error_keywords = ("{:s}={!s}".format(name, type.__name__ if isinstance(type, builtins.type) or type in {callable} else '|'.join(t_.__name__ for t_ in type) if hasattr(type, '__iter__') else "{!r}".format(type)) for name, type in t_args.items())
                raise internal.exceptions.InvalidParameterError(u"@{:s}({:s}) : The value ({!s}) specified for parameter \"{:s}\" is not a supported type.".format('.'.join([__name__, cls.__name__]), ', '.join(error_keywords), type, string.escape(name, '"')))
            continue

        # Validate the types of our arguments that we were asked to decorate with, this
        # way we can ensure that our previously decorated functions are actually of the
        # correct type. We do this strictly to assist with debugging.
        try:
            [cls.ex_function(item) for item in other]
        except Exception:
            error_keywords = ("{:s}={!s}".format(name, type.__name__ if isinstance(type, builtins.type) or type in {callable} else '|'.join(item.__name__ for item in type) if hasattr(type, '__iter__') else "{!r}".format(type)) for name, type in t_args.items())
            raise internal.exceptions.InvalidParameterError(u"@{:s}({:s}) : The specified callable{:s} {!r} {:s} not of a valid type.".format('.'.join([__name__, cls.__name__]), ', '.join(error_keywords), '' if len(other) == 1 else 's', other, 'is' if len(other) == 1 else 'are'))

        # If we were given an unexpected number of arguments to decorate with, then
        # raise an exception. This is strictly done to assist with debugging.
        if len(other) > 1:
            error_keywords = ("{:s}={!s}".format(name, type.__name__ if isinstance(type, builtins.type) or type in {callable} else '|'.join(item.__name__ for item in type) if hasattr(type, '__iter__') else "{!r}".format(type)) for name, type in t_args.items())
            raise internal.exceptions.InvalidParameterError(u"@{:s}({:s}) : More than one callable ({:s}) was specified to add a case to. Refusing to add cases to more than one callable.".format('.'.join([__name__, cls.__name__]), ', '.join(error_keywords), ', '.join("\"{:s}\"".format(string.escape(pycompat.code.name(c) if isinstance(c, types.CodeType) else c.__name__, '"')) for c in other)))
        return result

    @classmethod
    def document(cls, name, cache):
        '''Generate documentation for a multicased function.'''
        result = []

        # Iterate through every item in our cache, and generate the prototype for it.
        for function, constraints, (ignore_count, parameter_names, _, _) in cache:
            prototype = cls.prototype(function, constraints, parameter_names[:ignore_count])

            # Now that we have the prototype, we need to figure out where we need to
            # add the documentation for the individual case.
            doc = (function.__doc__ or '').split('\n')
            if len(doc) > 1:
                item, lines = "{:s} -> ".format(prototype), (item for item in doc)
                result.append("{:s}{:s}".format(item, next(lines)))
                result.extend("{: >{padding:d}s}".format(line, padding=len(item) + len(line)) for line in map(operator.methodcaller('strip'), lines))
            elif len(doc) == 1:
                result.append("{:s}{:s}".format(prototype, " -> {:s}".format(doc[0]) if len(doc[0]) else ''))
            continue
        return '\n'.join(result)

    @classmethod
    def flatten(cls, iterable):
        '''Take the provided `iterable` (or tree) and then yield each individual element resulting in it being "flattened".'''
        duplicates = {item for item in []}
        for item in iterable:
            if isinstance(item, (builtins.list, builtins.tuple, builtins.set)):
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
    def prototype(cls, function, constraints={}, ignored={item for item in []}):
        '''Generate a prototype for an instance of a `function`.'''
        args, defaults, (star, starstar) = cls.ex_args(function)

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
                if isinstance(constraint, builtins.type) or constraint in {callable}:
                    yield item, constraint.__name__
                elif hasattr(constraint, '__iter__'):
                    yield item, '|'.join(type.__name__ for type in cls.flatten(constraint))
                else:
                    yield item, "{!s}".format(constraint)
                continue
            return

        # Log any multicased functions that accidentally define type constraints for parameters
        # which don't actually exist. This is specifically done in order to aid debugging.
        unavailable = {constraint_name for constraint_name in constraints.keys()} - {argument_name for argument_name in args}
        if unavailable:
            co = pycompat.function.code(function)
            co_fullname, co_filename, co_lineno = '.'.join([function.__module__, function.__name__]), os.path.relpath(co.co_filename, idaapi.get_user_idadir()), co.co_firstlineno
            proto_s = "{:s}({:s}{:s}{:s})".format(co_fullname, ', '.join(args) if args else '', ", *{:s}".format(star) if star and args else "*{:s}".format(star) if star else '', ", **{:s}".format(starstar) if starstar and (star or args) else "**{:s}".format(starstar) if starstar else '')
            path_s = "{:s}:{:d}".format(co_filename, co_lineno)
            logging.warning("{:s}({:s}): Unable to constrain the type in {:s} for parameter{:s} ({:s}) at {:s}.".format('.'.join([__name__, 'multicase']), co_fullname, proto_s, '' if len(unavailable) == 1 else 's', ', '.join(unavailable), path_s))

        # Return the prototype for the current function with the provided parameter constraints.
        iterable = (item if parameter is None else "{:s}={:s}".format(item, parameter) for item, parameter in Femit_arguments(args, constraints, ignored))
        items = iterable, ["*{:s}".format(star)] if star else [], ["**{:s}".format(starstar)] if starstar else []
        return "{:s}({:s})".format(pycompat.function.name(function), ', '.join(itertools.chain(*items)))

    @classmethod
    def match(cls, packed_parameters, heap):
        '''Given the (`args`, `kwds`) stored in the `packed_parameters`, find the correct function according to the constraints of each member in the `heap`.'''
        args, kwds = packed_parameters

        # Iterate through all the available functions/cases within the heap that
        # we were given. This is being done in O(n) time which can be significantly
        # improved because we should be being sorted by complexity and count. This
        # really should allow use to start searching closer to the item in the list
        # that matches our parameters that we're searching with.
        for F, constraints, (parameter_ignore_count, parameter_names, parameter_defaults, (parameter_wildargs, parameter_wildkeywords)) in heap:

            # Grab our values that we're going to match with.
            parameter_iterator, parameter_keywords = (item for item in args), {kwparam : kwvalue for kwparam, kwvalue in kwds.items()}

            # Skip the ignored argument values within our parameters.
            [next(item) for item in [parameter_iterator] * parameter_ignore_count]

            # Build the argument tuple that contains the actual parameters that
            # will be passed to the matched function. When we collect the arguments,
            # we need to ensure that any keywords parameters and default parameters
            # will be inserted into the correct place within the tuple.
            parameter_values = []
            for name in parameter_names[parameter_ignore_count:]:
                try:
                    value = next(parameter_iterator)

                # If there were no parameters left within our iterator, then we
                # need to apply any keywords that we were given.
                except StopIteration:
                    if name in parameter_keywords:
                        value = parameter_keywords.pop(name)

                    # If there weren't any keywords with our parameter name, then
                    # we need to check to see if there's a default parameter to use.
                    elif name in parameter_defaults:
                        value = parameter_defaults.pop(name)

                    # If there were no default parameters, then we need to leave
                    # because we don't have a way to grab any more parameters.
                    else:
                        break

                    # We were able to get a keyword or default parameter, so we can
                    # add it to our arguments to match with.
                    parameter_values.append(value)

                # We consumed a parameter value, so we can now append it to our arguments
                # that we will match against.
                else:
                    parameter_values.append(value)
                continue

            # Now that we have our parameter values, we need to convert it into a tuple
            # so that we can process and use it. Any parameters left in parameter_iterator
            # or parameter_keywords are considered part of the wildcard parameters.
            argument_values = builtins.tuple(parameter_values)
            argument_wildcard, argument_keywords = [item for item in parameter_iterator], {kwparam : kwvalue for kwparam, kwvalue in parameter_keywords.items()}

            # First check if we have any extra parameters. If we do, but there's no wildcards
            # available in our current match, then it doesn't fit and we move onto the next one.
            if not parameter_wildargs and len(argument_wildcard):
                continue

            # If we have any extra keywords, then we need to ensure that there's a keyword
            # parameter in our current match. Otherwise, it doesn't fit and we need to move on.
            elif not parameter_wildkeywords and argument_keywords:
                continue

            # Second, we need to check that our argument length actually matches. To accomplish
            # this, we need to check if our function can take a wildcard parameter. If so, then
            # we need to ensure that the number of parameters that we were given are larger than
            # what was required.
            if parameter_wildargs and parameter_ignore_count + len(argument_values) < len(parameter_names):
                continue

            # If our function doesn't take a wildcard parameter, then our number of arguments
            # should match what we were given. If they don't, then skip onto the next one.
            elif not parameter_wildargs and parameter_ignore_count + len(argument_values) != len(parameter_names):
                continue

            # Third, we need to actually check our type constraints that our current match was
            # decorated with. If our constraint is a builtins.callable, then we just need to
            # ensure that the parameter can be called. Otherwise our constraint should be an
            # iterable of types that we can simply pass long to the isinstance() function.
            critiqueF = lambda constraint: builtins.callable if constraint == builtins.callable else frpartial(builtins.isinstance, constraint)

            # Zip our parameter names along with our argument values so that we can extract
            # the constraint, and check the value against it. If any of these checks fail,
            # then it's not a match and we need to move on to the next iteration.
            parameter_names_and_values = zip(parameter_names[parameter_ignore_count:], argument_values)
            if not all(critiqueF(constraints[name])(value) for name, value in parameter_names_and_values if name in constraints):
                continue

            # We should now have a match. So now that we've figured out all of our individual
            # parameters and their positions, we need to put them all together so that we can
            # return them to the caller so that they can actually call it.
            result_arguments = builtins.tuple(itertools.chain(args[:parameter_ignore_count], argument_values))
            return F, (result_arguments, argument_wildcard, argument_keywords)

        # If we iterated through everything in our heap, then we couldn't find a match for the
        # types the user gave us. So we need to raise an exception to inform the user that the
        # types we were given did not match any of the constraints that we know about.
        ignored = min(ignore_count for _, _, (ignore_count, _, _, _) in heap) if heap else 0
        error_arguments = [item.__class__.__name__ for item in args[ignored:]]
        error_keywords = ["{:s}={!s}".format(name, kwds[name].__class__.__name__) for name in kwds]

        # Here we extract all of the possible cases so that we can present a descriptive error
        # message. We also need to do something incredibly dirty here which involves re-splitting
        # the name from the prototypes to avoid re-calculating the name returned by cls.prototype.
        prototypes = ((F.__module__ if hasattr(F, '__module__') else None, cls.prototype(F, constraints)) for F, constraints, _ in heap)
        error_prototypes = ['.'.join([module, name]) if module else name for module, name in prototypes]
        error_names = sorted({prototype.split('(', 1)[0] for prototype in error_prototypes})

        # Now we can collect all of our components into individual lists of availability,
        # and then format them as a proper fucking sentence because we "love" our users.
        Fnames, Fhelp, Fprototype = "`{:s}`".format, "`help({:s})`".format, "{:s}".format
        available_names      = ', '.join(map(Fnames,     error_names[:-1]))      + (", and {:s}".format(*map(Fnames,     error_names[-1:]))      if len(error_names) > 1      else Fnames(error_names[0]))
        available_help       = ', '.join(map(Fhelp,      error_names[:-1]))      + (", and {:s}".format(*map(Fhelp,      error_names[-1:]))      if len(error_names) > 1      else Fhelp(error_names[0]))
        available_prototypes = ', '.join(map(Fprototype, error_prototypes[:-1])) + (", or {:s}".format( *map(Fprototype, error_prototypes[-1:])) if len(error_prototypes) > 1 else Fprototype(error_prototypes[0]))

        # Now we can format our description, create our exception, and finally raise it.
        description = ', '.join("{:s}({:s}{:s})".format(name, ', '.join(error_arguments) if args else '*()', ", {:s}".format(', '.join(error_keywords)) if error_keywords else '') for name in error_names)
        raise internal.exceptions.UnknownPrototypeError(u"{:s}: The given parameter{:s} not match any of the available prototypes for {:s}. The prototypes which are available via {:s} are: {:s}".format(description, ' does' if sum(map(len, [error_arguments, error_keywords])) == 1 else 's do', available_names, available_help, available_prototypes))

    @classmethod
    def new_wrapper(cls, func, cache):
        '''Create a new wrapper that will determine the correct function to call.'''

        # Define the wrapper for the function that we're decorating. This way whenever the
        # decorated function gets called, we can search for one that matches the correct
        # constraints and dispatch into it with the original parameters in the correct order.
        def F(*arguments, **keywords):
            heap = [item for _, item in heapq.nsmallest(len(cache), cache, key=operator.attrgetter('priority'))]

            # Pack our parameters, and then hand them off to our matching function. This
            # should then return the correct callable that matches the argument types we
            # were given so that we can dispatch to it.
            packed_parameters = arguments, keywords
            result_callable, result_parameters = cls.match(packed_parameters, heap)

            # Now we have a matching callable for the user's parameters, and we just need
            # to unpack our individual parameters and dispatch to the callable with them.
            parameters, wild_parameters, keyword_parameters = result_parameters
            return result_callable(*itertools.chain(parameters, wild_parameters), **keyword_parameters)

        # First, we need to swap out the original code object with the one from the closure
        # that we defined. In order to preserve information within the backtrace, we just
        # make a copy of all of the relevant code properties.
        f, c = F, pycompat.function.code(F)
        cargs = c.co_argcount, c.co_nlocals, c.co_stacksize, c.co_flags, \
                c.co_code, c.co_consts, c.co_names, c.co_varnames, \
                c.co_filename, '.'.join([func.__module__, pycompat.function.name(func)]), \
                c.co_firstlineno, c.co_lnotab, c.co_freevars, c.co_cellvars
        newcode = pycompat.code.new(cargs, pycompat.code.unpack_extra(c))

        # Now we can use the new code object that we created in order to create a function
        # and assign the previous name and documentation into it.
        result = pycompat.function.new(newcode, pycompat.function.globals(f), pycompat.function.name(f), pycompat.function.defaults(f), pycompat.function.closure(f))
        pycompat.function.set_name(result, pycompat.function.name(func)),
        pycompat.function.set_documentation(result, pycompat.function.documentation(func))

        # The last two things to do is to copy our cache that we were given into the function
        # that we're going to return. This way people can debug it if they feel they need to.
        setattr(result, cls.cache_name, cache)
        setattr(result, '__doc__', '')
        return result

    @classmethod
    def ex_function(cls, object):
        '''Extract the actual function type from a callable.'''
        if isinstance(object, types.FunctionType):
            return object
        elif isinstance(object, types.MethodType):
            return pycompat.method.function(object)
        elif isinstance(object, types.CodeType):
            res, = (item for item in gc.get_referrers(c) if pycompat.function.name(item) == pycompat.code.name(c) and isinstance(item, types.FunctionType))
            return res
        elif isinstance(object, (staticmethod, classmethod)):
            return object.__func__
        raise internal.exceptions.InvalidTypeOrValueError(object)

    @classmethod
    def reconstructor(cls, item):
        '''Return a closure that returns the original callable type for a function.'''
        if isinstance(item, types.FunctionType):
            return lambda f: f
        if isinstance(item, types.MethodType):
            return lambda f: pycompat.method.new(f, pycompat.method.self(item), pycompat.method.type(item))
        if isinstance(item, (staticmethod, classmethod)):
            return lambda f: type(item)(f)
        if isinstance(item, types.InstanceType):
            return lambda f: types.InstanceType(type(item), dict(f.__dict__))
        if isinstance(item, (builtins.type, types.ClassType)):
            return lambda f: type(item)(item.__name__, item.__bases__, dict(f.__dict__))
        raise internal.exceptions.InvalidTypeOrValueError(type(item))

    @classmethod
    def ex_args(cls, f):
        '''Extract the arguments from a function.'''
        c = pycompat.function.code(f)
        varnames_count, varnames_iter = pycompat.code.argcount(c), (item for item in pycompat.code.varnames(c))
        args = tuple(itertools.islice(varnames_iter, varnames_count))
        res = { a : v for v, a in zip(reversed(pycompat.function.defaults(f) or []), reversed(args)) }
        try: starargs = next(varnames_iter) if pycompat.code.flags(c) & pycompat.co_flags.CO_VARARGS else ""
        except StopIteration: starargs = ""
        try: kwdargs = next(varnames_iter) if pycompat.code.flags(c) & pycompat.co_flags.CO_VARKEYWORDS else ""
        except StopIteration: kwdargs = ""
        return args, res, (starargs, kwdargs)

    @classmethod
    def generatorQ(cls, func):
        '''Returns true if `func` is a generator.'''
        func = cls.ex_function(func)
        code = pycompat.function.code(func)
        return bool(pycompat.code.flags(code) & CO_VARGEN)

class alias(object):
    def __new__(cls, other, klass=None):
        cons, func = multicase.reconstructor(other), multicase.ex_function(other)
        if isinstance(other, types.MethodType) or klass:
            module = (func.__module__, klass or pycompat.method.type(other).__name__)
        else:
            module = (func.__module__,)
        document = "Alias for `{:s}`.".format('.'.join(module + (pycompat.function.name(func),)))
        res = cls.new_wrapper(func, document)
        return cons(res)

    @classmethod
    def new_wrapper(cls, func, document):
        # build the wrapper...
        def fn(*arguments, **keywords):
            return func(*arguments, **keywords)
        res = functools.update_wrapper(fn, func)
        res.__doc__ = document
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
        res = [(operator.attrgetter(callable_or_attribute) if isinstance(callable_or_attribute, six.string_types) else callable_or_attribute) for callable_or_attribute in attributes]
        return fcompose(*res) if len(res) > 1 else res[0]
    def attribute(self, type, *attribute):
        attr = self.__attrib__(*attribute)
        self.__predicate__[type] = lambda target: fcompose(attr, functools.partial(functools.partial(operator.eq, target)))
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
        matcher = self.__predicate__[type](value)
        return (item for item in iterable if matcher(item))

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
            elif isinstance(ch, six.string_types) and cls.asciiQ(ch):
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
        if isinstance(item, six.string_types) and sys.version_info.major < 3:
            res = cls.escape(item.decode('latin1') if isinstance(item, bytes) else item, u'\'')
            if all(ord(ch) < 0x100 for ch in item):
                return u"'{:s}'".format(res)
            return u"u'{:s}'".format(res)

        # Python3 string types (str and bytes)
        elif isinstance(item, six.string_types):
            res = cls.escape(item, u'\'')
            return u"'{:s}'".format(res)

        elif isinstance(item, bytes):
            res = cls.escape(item.decode('latin1'), u'\'')
            return u"b'{:s}'".format(res)

        elif isinstance(item, tuple):
            res = map(cls.repr, item)
            return u"({:s}{:s})".format(', '.join(res), ',' if len(item) == 1 else '')

        elif isinstance(item, list):
            res = map(cls.repr, item)
            return u"[{:s}]".format(', '.join(res))

        elif isinstance(item, set):
            res = map(cls.repr, item)
            return u"set([{:s}])".format(', '.join(res))

        elif isinstance(item, dict):
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

    # Python2 implementation of the assemble function which will take a callable, pass it as the first
    # parameter to some kind of wrapper (callable) whilst preserving any arguments/names that were called.
    @classmethod
    def assemble_2x(cls, function, wrapper, bound=False):
        """Assemble a ``types.CodeType`` that will execute `wrapper` with `F` as its first parameter.

        If `bound` is ``True``, then assume that the first parameter for `F` represents the instance it's bound to.
        """
        F, C, S = (cls.extract(item) for item in [function, wrapper, cls.assemble_2x])
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
        cargs = pycompat.code.cons( \
                    len(Fargs), len(co_names) + len(co_varnames) + len(co_freevars), \
                    co_stacksize, co_flags, co_code, \
                    co_consts, co_names, co_varnames, \
                    Fc.co_filename, Fc.co_name, Fc.co_firstlineno, \
                    bytes(), co_freevars, ()
                )

        func_code = pycompat.code.new(cargs)

        ## and then turn it back into a function
        res = pycompat.function.new(func_code, pycompat.function.globals(F), pycompat.function.name(F), pycompat.function.defaults(F), cls.cell(*Svals))
        pycompat.function.set_name(res, pycompat.function.name(F)),
        pycompat.function.set_documentation(res, pycompat.function.documentation(F))

        return res

    # Python3 implementation of the assemble function which will take a callable, pass it as the first
    # parameter to some kind of wrapper (callable) whilst preserving any arguments/names that were called.
    @classmethod
    def assemble_38x(cls, function, wrapper, bound=False):
        """Assemble a ``types.CodeType`` that will execute `wrapper` with `F` as its first parameter.

        If `bound` is ``True``, then assume that the first parameter for `F` represents the instance it's bound to.
        """
        F, C, S = (cls.extract(item) for item in [function, wrapper, cls.assemble_38x])
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
        cargs = pycompat.code.cons( \
                    len(Fargs), len(co_names) + len(co_varnames) + len(co_freevars), \
                    co_stacksize, co_flags, co_code, \
                    co_consts, co_names, co_varnames, \
                    Fc.co_filename, Fc.co_name, Fc.co_firstlineno, \
                    bytes(), co_freevars, ()
                )

        func_code = pycompat.code.new(cargs)

        ## finally take our code object, and put it back into a function/callable.
        res = pycompat.function.new(func_code, pycompat.function.globals(F), pycompat.function.name(F), pycompat.function.defaults(F), cls.cell(*Svals))
        pycompat.function.set_name(res, pycompat.function.name(F)),
        pycompat.function.set_documentation(res, pycompat.function.documentation(F))

        return res

    @classmethod
    def assemble_39x(cls, function, wrapper, bound=False):
        """Assemble a ``types.CodeType`` that will execute `wrapper` with `F` as its first parameter.

        If `bound` is ``True``, then assume that the first parameter for `F` represents the instance it's bound to.
        """
        F, C, S = (cls.extract(item) for item in [function, wrapper, cls.assemble_39x])
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
        cargs = pycompat.code.cons( \
                    len(Fargs), len(co_names) + len(co_varnames) + len(co_freevars) if sys.version_info.minor < 11 else len(co_varnames), \
                    co_stacksize, co_flags, co_code, \
                    co_consts, co_names, co_varnames, \
                    Fc.co_filename, Fc.co_name, Fc.co_firstlineno, \
                    bytes(), co_freevars, ()
                )

        func_code = pycompat.code.new(cargs)

        ## finally take our code object, and put it back into a function/callable.
        res = pycompat.function.new(func_code, pycompat.function.globals(F), pycompat.function.name(F), pycompat.function.defaults(F), cls.cell(*Svals))
        pycompat.function.set_name(res, pycompat.function.name(F)),
        pycompat.function.set_documentation(res, pycompat.function.documentation(F))

        return res

    def __new__(cls, callable, wrapper):
        '''Return a function similar to `callable` that calls `wrapper` with `callable` as the first argument.'''
        cons, f = cls.constructor(callable), cls.extract(callable)
        Fassemble = cls.assemble_2x if sys.version_info.major < 3 else cls.assemble_38x if sys.version_info.minor < 9 else cls.assemble_39x

        # create a wrapper for the function that'll execute `callable` with the function as its first argument, and the rest with any args
        res = Fassemble(callable, wrapper, bound=isinstance(callable, (classmethod, types.MethodType)))
        res.__module__ = getattr(callable, '__module__', getattr(callable, '__module__', '__main__'))

        # now we re-construct it and then return it
        return cons(res)

    @classmethod
    def extract(cls, object):
        '''Extract a ``types.FunctionType`` from a callable.'''

        # `object` is already a function
        if isinstance(object, types.FunctionType):
            return object

        # if it's a method, then extract the function from its propery
        elif isinstance(object, types.MethodType):
            return pycompat.method.function(object)

        # if it's a code type, then walk through all of its referrers finding one that matches it
        elif isinstance(object, types.CodeType):
            res, = (item for item in gc.get_referrers(c) if pycompat.function.name(item) == pycompat.code.name(c) and isinstance(item, types.FunctionType))
            return res

        # if it's a property decorator, then they hide the function in an attribute
        elif isinstance(object, (staticmethod, classmethod)):
            return object.__func__

        # okay, no go. we have no idea what this is.
        raise internal.exceptions.InvalidTypeOrValueError(object)

    @classmethod
    def arguments(cls, f):
        '''Extract the arguments from a function `f`.'''
        c = pycompat.function.code(f)
        count, iterable = pycompat.code.argcount(c), (item for item in pycompat.code.varnames(c))
        args = tuple(itertools.islice(iterable, count))
        res = { a : v for v, a in zip(reversed(pycompat.function.defaults(f) or []), reversed(args)) }
        starargs = next(iterable, '') if pycompat.code.flags(c) & pycompat.co_flags.CO_VARARGS else ''
        kwdargs = next(iterable, '') if pycompat.code.flags(c) & pycompat.co_flags.CO_VARKEYWORDS else ''
        return args, res, (starargs, kwdargs)

    @classmethod
    def constructor(cls, callable):
        '''Return a closure that constructs the original `callable` type from a function.'''

        # `callable` is a function type, so just return a closure that returns it
        if isinstance(callable, types.FunctionType):
            return lambda func: func

        # if it's a method type, then we just need to extract the related properties to construct it
        elif isinstance(callable, types.MethodType):
            return lambda method, self=pycompat.method.self(callable), cls=pycompat.method.type(callable): pycompat.method.new(method, self, cls)

        # if it's a property decorator, we just need to pass the function as an argument to the decorator
        elif isinstance(callable, (staticmethod, classmethod)):
            return lambda method, mt=callable.__class__: mt(method)

        # if it's a method instance, then we just need to instantiate it so that it's bound
        elif isinstance(callable, types.InstanceType):
            return lambda method, mt=callable.__class__: types.InstanceType(mt, dict(method.__dict__))

        # otherwise if it's a class or a type, then we just need to create the object with its bases
        elif isinstance(n, (builtins.type, types.ClassType)):
            return lambda method, t=callable.__class__, name=callable.__name__, bases=callable.__bases__: t(name, bases, dict(method.__dict__))

        # if we get here, then we have no idea what kind of type `callable` is
        raise internal.exceptions.InvalidTypeOrValueError(callable.__class__)

### function decorator for translating arguments belonging to a function
def transform(translate, *names):
    '''This applies the callable `translate` to any function arguments that match `names` in the decorated function.'''
    names = {name for name in names}
    def wrapper(F, *rargs, **rkwds):
        f = wrap.extract(F)
        argnames, defaults, (wildname, _) = wrap.arguments(f)

        # convert any positional arguments
        res = ()
        for value, argname in zip(rargs, argnames):
            try:
                res += (translate(value) if argname in names else value),
            except Exception as E:
                cls = E.__class__
                raise cls("{!s}: Exception raised while transforming parameter `{:s}` with value {!r}".format('.'.join([f.__module__, f.__name__]), argname, value))

        # get the rest
        for value in rargs[len(res):]:
            try:
                res += (translate(value) if wildname in names else value,)
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
