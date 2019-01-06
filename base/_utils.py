"""
Utilities module (internal)

This module contains a number of tools that help with the interface for this
plugin. This contains things such as the multicase decorator, the matcher
class for querying and filtering lists of things, support for aliasing
functions, and a number of functional programming primitives (combinators).
"""

import six
from six.moves import builtins

import logging, types, weakref
import functools, operator, itertools
import sys, heapq, collections

import internal
import idaapi

__all__ = ['fbox','fboxed','funbox','finstance','fhasitem','fitemQ','fgetitem','fitem','fhasattr','fattributeQ','fgetattr','fattribute','fconstant','fpassthru','fdefault','fpass','fidentity','fid','first','second','third','last','fcompose','fdiscard','fcondition','fmap','flazy','fmemo','fpartial','fapply','fcurry','frpartial','freverse','freversed','fexc','fexception','fcatch','fcomplement','fnot','ilist','liter','ituple','titer','itake','iget','imap','ifilter','ichain','izip','count']

### functional programming primitives (FIXME: probably better to document these with examples)

# box any specified arguments
fbox = fboxed = lambda *a: a
# return a closure that executes `f` with the arguments unboxed.
funbox = lambda f, *a, **k: lambda *ap, **kp: f(*(a + builtins.reduce(operator.add, builtins.map(builtins.tuple, ap), ())), **builtins.dict(k.items() + kp.items()))
# return a closure that will check that `object` is an instance of `type`.
finstance = lambda *type: frpartial(builtins.isinstance, type)
# return a closure that will check if its argument has an item `key`.
fhasitem = fitemQ = lambda key: fcompose(fcatch(frpartial(operator.getitem, key)), iter, next, fpartial(operator.eq, None))
# return a closure that will get a particular element from an object
fgetitem = fitem = lambda item, *default: lambda object: default[0] if default and item not in object else object[item]
# return a closure that will check if its argument has an `attribute`.
fhasattr = fattributeQ = lambda attribute: frpartial(hasattr, attribute)
# return a closure that will get a particular attribute from an object
fgetattr = fattribute = lambda attribute, *default: lambda object: getattr(object, attribute, *default)
# return a closure that always returns `object`.
fconstant = fconst = falways = lambda object: lambda *a, **k: object
# a closure that returns its argument always
fpassthru = fpass = fidentity = fid = lambda object: object
# a closure that returns a default value if its object is false-y
fdefault = lambda default: lambda object: object or default
# return the first, second, or third item of a box.
first, second, third, last = operator.itemgetter(0), operator.itemgetter(1), operator.itemgetter(2), operator.itemgetter(-1)
# return a closure that executes a list of functions one after another from left-to-right
fcompose = lambda *f: builtins.reduce(lambda f1, f2: lambda *a: f1(f2(*a)), builtins.reversed(f))
# return a closure that executes function `f` whilst discarding any extra arguments
fdiscard = lambda f: lambda *a, **k: f()
# return a closure that executes function `crit` and then returns/executes `f` or `t` based on whether or not it's successful.
fcondition = fcond = lambda crit: lambda t, f: \
    lambda *a, **k: (t(*a, **k) if builtins.callable(t) else t) if crit(*a, **k) else (f(*a, **k) if builtins.callable(f) else f)
# return a closure that takes a list of functions to execute with the provided arguments
fmap = lambda *fa: lambda *a, **k: (f(*a, **k) for f in fa)
#lazy = lambda f, state={}: lambda *a, **k: state[(f, a, builtins.tuple(builtins.sorted(k.items())))] if (f, a, builtins.tuple(builtins.sorted(k.items()))) in state else state.setdefault((f, a, builtins.tuple(builtins.sorted(k.items()))), f(*a, **k))
#lazy = lambda f, *a, **k: lambda *ap, **kp: f(*(a+ap), **dict(k.items() + kp.items()))
# return a memoized closure that's lazy and only executes when evaluated
def flazy(f, *a, **k):
    sortedtuple, state = fcompose(builtins.sorted, builtins.tuple), {}
    def lazy(*ap, **kp):
        A, K = a+ap, sortedtuple(k.items() + kp.items())
        return state[(A, K)] if (A, K) in state else state.setdefault((A, K), f(*A, **builtins.dict(k.items()+kp.items())))
    return lazy
fmemo = flazy
# return a closure with the function's arglist partially applied
fpartial = functools.partial
# return a closure that applies the provided arguments to the function `f`.
fapply = lambda f, *a, **k: lambda *ap, **kp: f(*(a+ap), **builtins.dict(k.items() + kp.items()))
# return a closure that will use the specified arguments to call the provided function.
fcurry = lambda *a, **k: lambda f, *ap, **kp: f(*(a+ap), **builtins.dict(k.items() + kp.items()))
# return a closure that applies the initial arglist to the end of function `f`.
frpartial = lambda f, *a, **k: lambda *ap, **kp: f(*(ap + builtins.tuple(builtins.reversed(a))), **builtins.dict(k.items() + kp.items()))
# return a closure that applies the arglist to function `f` in reverse.
freversed = freverse = lambda f, *a, **k: lambda *ap, **kp: f(*builtins.reversed(a + ap), **builtins.dict(k.items() + kp.items()))
# return a closure that executes function `f` and includes the caught exception (or None) as the first element in the boxed result.
def fcatch(f, *a, **k):
    def fcatch(*a, **k):
        try: return builtins.None, f(*a, **k)
        except: return sys.exc_info()[1], builtins.None
    return functools.partial(fcatch, *a, **k)
fexc = fexception = fcatch
# boolean inversion of the result of a function
fcomplement = fnot = frpartial(fcompose, operator.not_)
# converts a list to an iterator, or an iterator to a list
ilist, liter = fcompose(builtins.list, builtins.iter), fcompose(builtins.iter, builtins.list)
# converts a tuple to an iterator, or an iterator to a tuple
ituple, titer = fcompose(builtins.tuple, builtins.iter), fcompose(builtins.iter, builtins.tuple)
# take `count` number of elements from an iterator
itake = lambda count: fcompose(builtins.iter, fmap(*(builtins.next,)*count), builtins.tuple)
# get the `nth` element from an iterator
iget = lambda count: fcompose(builtins.iter, fmap(*(builtins.next,)*(count)), builtins.tuple, operator.itemgetter(-1))
# copy from itertools
imap, ifilter, ichain, izip = itertools.imap, itertools.ifilter, itertools.chain, itertools.izip
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
    def __init__(self, other):
        self.type = other
    def __cmp__(self, other):
        return 0 if isinstance(other, self.type) else -1
    def __repr__(self):
        return "{:s}({:s})".format('Pattern', '|'.join(n.__name__ for n in self.type) if hasattr(self.type, '__iter__') else self.type.__name__)

### decorators
class multicase(object):
    """
    A lot of magic is in this class which allows one to define multiple cases
    for a single function.
    """
    CO_OPTIMIZED                = 0x00001
    CO_NEWLOCALS                = 0x00002
    CO_VARARGS                  = 0x00004
    CO_VARKEYWORDS              = 0x00008
    CO_NESTED                   = 0x00010
    CO_VARGEN                   = 0x00020
    CO_NOFREE                   = 0x00040
    CO_COROUTINE                = 0x00080
    CO_ITERABLE                 = 0x00100
    CO_GENERATOR_ALLOWED        = 0x01000
    CO_FUTURE_DIVISION          = 0x02000
    CO_FUTURE_ABSOLUTE_IMPORT   = 0x04000
    CO_FUTURE_WITH_STATEMENT    = 0x08000
    CO_FUTURE_PRINT_FUNCTION    = 0x10000
    CO_FUTURE_UNICODE_LITERALS  = 0x20000
    CO_FUTURE_BARRY_AS_BDFL     = 0x40000
    CO_FUTURE_GENERATOR_STOP    = 0x80000

    cache_name = '__multicase_cache__'

    def __new__(cls, *other, **t_args):
        '''Decorate a case of a function with the specified types.'''
        def result(wrapped):
            # extract the FunctionType and its arg types
            cons, func = cls.reconstructor(wrapped), cls.ex_function(wrapped)
            args, defaults, (star, starstar) = cls.ex_args(func)
            s_args = 1 if isinstance(wrapped, (classmethod, types.MethodType)) else 0

            # determine if the user included the previous function
            if len(other):
                ok, prev = True, other[0]
            # ..otherwise we just figure it out by looking in the caller's locals
            elif func.func_name in sys._getframe().f_back.f_locals:
                ok, prev = True, sys._getframe().f_back.f_locals[func.func_name]
            # ..otherwise, first blood and we're not ok.
            else:
                ok = False

            # so, a wrapper was found and we need to steal its cache
            res = ok and cls.ex_function(prev)
            if ok and hasattr(res, cls.cache_name):
                cache = getattr(res, cls.cache_name)
            # ..otherwise, we just create a new one.
            else:
                cache = []
                res = cls.new_wrapper(func, cache)
                res.__module__ = getattr(wrapped, '__module__', getattr(func, '__module__', '__main__'))

            # calculate the priority by trying to match the most first
            argtuple = s_args, args, defaults, (star, starstar)
            priority = len(args) - s_args - len(t_args) + (len(args) and (next((float(i) for i, a in enumerate(args[s_args:]) if a in t_args), 0) / len(args))) + sum(0.3 for _ in filter(None, (star, starstar)))

            # check to see if our func is already in the cache
            current = tuple(t_args.get(_, None) for _ in args), (star, starstar)
            for i, (p, (_, t, a)) in enumerate(cache):
                if p != priority: continue
                # verify that it actually matches the entry
                if current == (tuple(t.get(_, None) for _ in a[1]), a[3]):
                    # yuuup, update it.
                    cache[i] = (priority, (func, t_args, argtuple))
                    res.__doc__ = cls.document(func.__name__, [n for _, n in cache])
                    return cons(res)
                continue

            # everything is ok...so should be safe to add it
            heapq.heappush(cache, (priority, (func, t_args, argtuple)))

            # now we can update the docs
            res.__doc__ = cls.document(func.__name__, [n for _, n in cache])

            # ..and then restore the wrapper to its former glory
            return cons(res)

        # validate type arguments
        for n, t in t_args.iteritems():
            if not isinstance(t, (types.TypeType, types.TupleType)) and t not in {callable}:
                error_keywords = ("{:s}={!s}".format(n, t.__name__ if isinstance(t, types.TypeType) or t in {callable} else '|'.join(t_.__name__ for t_ in t) if hasattr(t, '__iter__') else "{!r}".format(t)) for n, t in t_args.iteritems())
                raise internal.exceptions.InvalidParameterError(u"@{:s}({:s}) : The value ({!s}) specified for parameter \"{:s}\" is not a supported type.".format('.'.join(('internal', __name__, cls.__name__)), ', '.join(error_keywords), t, string.escape(n, '"')))
            continue

        # validate arguments containing original callable
        try:
            for c in other:
                cls.ex_function(c)
        except:
            error_keywords = ("{:s}={!s}".format(n, t.__name__ if isinstance(t, types.TypeType) or t in {callable} else '|'.join(t_.__name__ for t_ in t) if hasattr(t, '__iter__') else "{!r}".format(t)) for n, t in t_args.iteritems())
            raise internal.exceptions.InvalidParameterError(u"@{:s}({:s}) : The specified callable{:s} {!r} {:s} not of a valid type.".format('.'.join(('internal', __name__, cls.__name__)), ', '.join(error_keywords), '' if len(other) == 1 else 's', other, 'is' if len(other) == 1 else 'are'))

        # throw an exception if we were given an unexpected number of arguments
        if len(other) > 1:
            error_keywords = ("{:s}={!s}".format(n, t.__name__ if isinstance(t, types.TypeType) or t in {callable} else '|'.join(t_.__name__ for t_ in t) if hasattr(t, '__iter__') else "{!r}".format(t)) for n, t in t_args.iteritems())
            raise internal.exceptions.InvalidParameterError(u"@{:s}({:s}) : More than one callable ({:s}) was specified to add a case to. Refusing to add cases to more than one callable.".format('.'.join(('internal', __name__, cls.__name__)), ', '.join(error_keywords), ', '.join("\"{:s}\"".format(string.escape(c.co_name if isinstance(c, types.CodeType) else c.__name__, '"')) for c in other)))
        return result

    @classmethod
    def document(cls, name, cache):
        '''Generate documentation for a multicased function.'''
        res = []
        for func, types, _ in cache:
            doc = (func.__doc__ or '').split('\n')
            if len(doc) > 1:
                res.append("{:s} ->".format(cls.prototype(func, types)))
                res.extend("{: >{padding:d}s}".format(n, padding=len(name)+len(n)+1) for n in map(operator.methodcaller('strip'), doc))
            elif len(doc) == 1:
                res.append(cls.prototype(func, types) + (" -> {:s}".format(doc[0]) if len(doc[0]) else ''))
            continue
        return '\n'.join(res)

    @classmethod
    def prototype(cls, func, parameters={}):
        '''Generate a prototype for an instance of a function.'''
        args, defaults, (star, starstar) = cls.ex_args(func)
        argsiter = ("{:s}={:s}".format(n, parameters[n].__name__ if isinstance(parameters[n], types.TypeType) or parameters[n] in {callable} else '|'.join(t.__name__ for t in parameters[n]) if hasattr(parameters[n], '__iter__') else "{!r}".format(parameters[n])) if parameters.has_key(n) else n for n in args)
        res = (argsiter, ("*{:s}".format(star),) if star else (), ("**{:s}".format(starstar),) if starstar else ())
        return "{:s}({:s})".format(func.func_name, ', '.join(itertools.chain(*res)))

    @classmethod
    def match(cls, (args, kwds), heap):
        '''Given the specified `args` and `kwds`, find the correct function according to its types.'''
        # FIXME: yep, done in O(n) time.
        for f, ts, (sa, af, defaults, (argname, kwdname)) in heap:
            # populate our arguments
            ac, kc = (n for n in args), dict(kwds)

            # skip some args in our tuple
            map(next, (ac,)*sa)

            # build the argument tuple using the generator, kwds, or our defaults.
            a = []
            try:
                for n in af[sa:]:
                    try: a.append(next(ac))
                    except StopIteration: a.append(kc.pop(n) if n in kc else defaults.pop(n))
            except KeyError: pass
            finally: a = tuple(a)

            # now anything left in ac or kc goes in the wildcards. if there aren't any, then this iteration doesn't match.
            wA, wK = list(ac), dict(kc)
            if (not argname and len(wA)) or (not kwdname and wK):
                continue

            # if our perceived argument length doesn't match, then this iteration doesn't match either
            if len(a) != len(af[sa:]):
                continue

            # figure out how to match the types by checking if it's a regular type or it's a callable
            predicateF = lambda t: callable if t == callable else (lambda v: isinstance(v, t))

            # now we can finally start checking that the types match
            if any(not predicateF(ts[t])(v) for t, v in zip(af[sa:], a) if t in ts):
                continue

            # we should have a match
            return f, (tuple(args[:sa]) + a, wA, wK)

        error_arguments = [n.__class__.__name__ for n in args]
        error_keywords = ["{:s}={!s}".format(n, kwds[n].__class__.__name__) for n in kwds]
        raise internal.exceptions.UnknownPrototypeError(u"@multicase.call({:s}{:s}): The requested argument types do not match any of the available prototypes. The prototypes that are available are: {:s}.".format(', '.join(error_arguments) if args else '*()', ", {:s}".format(', '.join(error_keywords)) if error_keywords else '', ', '.join(cls.prototype(f, t) for f, t, _ in heap)))

    @classmethod
    def new_wrapper(cls, func, cache):
        '''Create a new wrapper that will determine the correct function to call.'''
        # define the wrapper...
        def F(*arguments, **keywords):
            heap = [res for _, res in heapq.nsmallest(len(cache), cache)]
            f, (a, w, k) = cls.match((arguments[:], keywords), heap)
            return f(*arguments, **keywords)
            #return f(*(arguments + tuple(w)), **keywords)

        # swap out the original code object with our wrapper's
        f, c = F, F.func_code
        cargs = c.co_argcount, c.co_nlocals, c.co_stacksize, c.co_flags, \
                c.co_code, c.co_consts, c.co_names, c.co_varnames, \
                c.co_filename, '.'.join((func.__module__, func.func_name)), \
                c.co_firstlineno, c.co_lnotab, c.co_freevars, c.co_cellvars
        newcode = types.CodeType(*cargs)
        res = types.FunctionType(newcode, f.func_globals, f.func_name, f.func_defaults, f.func_closure)
        res.func_name, res.func_doc = func.func_name, func.func_doc

        # assign the specified cache to it
        setattr(res, cls.cache_name, cache)
        # ...and finally add a default docstring
        setattr(res, '__doc__', '')
        return res

    @classmethod
    def ex_function(cls, object):
        '''Extract the actual function type from a callable.'''
        if isinstance(object, types.FunctionType):
            return object
        elif isinstance(object, types.MethodType):
            return object.im_func
        elif isinstance(object, types.CodeType):
            res, = (n for n in gc.get_referrers(c) if n.func_name == c.co_name and isinstance(n, types.FunctionType))
            return res
        elif isinstance(object, (staticmethod, classmethod)):
            return object.__func__
        raise internal.exceptions.InvalidTypeOrValueError(object)

    @classmethod
    def reconstructor(cls, n):
        '''Return a closure that returns the original callable type for a function.'''
        if isinstance(n, types.FunctionType):
            return lambda f: f
        if isinstance(n, types.MethodType):
            return lambda f: types.MethodType(f, n.im_self, n.im_class)
        if isinstance(n, (staticmethod, classmethod)):
            return lambda f: type(n)(f)
        if isinstance(n, types.InstanceType):
            return lambda f: types.InstanceType(type(n), dict(f.__dict__))
        if isinstance(n, (types.TypeType, types.ClassType)):
            return lambda f: type(n)(n.__name__, n.__bases__, dict(f.__dict__))
        raise internal.exceptions.InvalidTypeOrValueError(type(n))

    @classmethod
    def ex_args(cls, f):
        '''Extract the arguments from a function.'''
        c = f.func_code
        varnames_count, varnames_iter = c.co_argcount, iter(c.co_varnames)
        args = tuple(itertools.islice(varnames_iter, varnames_count))
        res = { a : v for v, a in zip(reversed(f.func_defaults or []), reversed(args)) }
        try: starargs = next(varnames_iter) if c.co_flags & cls.CO_VARARGS else ""
        except StopIteration: starargs = ""
        try: kwdargs = next(varnames_iter) if c.co_flags & cls.CO_VARKEYWORDS else ""
        except StopIteration: kwdargs = ""
        return args, res, (starargs, kwdargs)

    @classmethod
    def generatorQ(cls, func):
        '''Returns true if `func` is a generator.'''
        func = cls.ex_function(func)
        return bool(func.func_code.co_flags & CO_VARGEN)

class alias(object):
    def __new__(cls, other, klass=None):
        cons, func = multicase.reconstructor(other), multicase.ex_function(other)
        if isinstance(other, types.MethodType) or klass:
            module = (func.__module__, klass or other.im_self.__name__)
        else:
            module = (func.__module__,)
        document = "Alias for `{:s}`.".format('.'.join(module + (func.func_name,)))
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

### namespace for asynchronous process monitor
class Asynchronous:
    import threading
    Thread, Event = map(staticmethod, (threading.Thread, threading.Event))

    import Queue
    Queue, QueueEmptyException = map(staticmethod, (Queue.Queue, Queue.Empty))

    import subprocess
    spawn, spawn_options = map(staticmethod, (subprocess.Popen, subprocess))

### warm up some pasta
import sys, os, weakref, time, itertools, shlex

# monitoring an external process' i/o via threads/queues
class process(object):
    """Spawns a program along with a few monitoring threads for allowing asynchronous(heh) interaction with a subprocess.

    mutable properties:
    program -- Asynchronous.spawn result
    commandline -- Asynchronous.spawn commandline
    eventWorking -- Asynchronous.Event() instance for signalling task status to monitor threads
    stdout,stderr -- callables that are used to process available work in the taskQueue

    properties:
    id -- subprocess pid
    running -- returns true if process is running and monitor threads are workingj
    working -- returns true if monitor threads are working
    threads -- list of threads that are monitoring subprocess pipes
    taskQueue -- Asynchronous.Queue() instance that contains work to be processed
    exceptionQueue -- Asynchronous.Queue() instance containing exceptions generated during processing
    (process.stdout, process.stderr)<Queue> -- Queues containing output from the spawned process.
    """

    program = None              # Asynchronous.spawn result
    id = property(fget=lambda self: self.program and self.program.pid or -1)
    running = property(fget=lambda self: False if self.program is None else self.program.poll() is None)
    working = property(fget=lambda self: self.running and not self.eventWorking.is_set())
    threads = property(fget=lambda self: list(self.__threads))
    updater = property(fget=lambda self: self.__updater)

    taskQueue = property(fget=lambda self: self.__taskQueue)
    exceptionQueue = property(fget=lambda self: self.__exceptionQueue)

    def __init__(self, command, **kwds):
        """Creates a new instance that monitors Asynchronous.spawn(`command`), the created process starts in a paused state.

        Keyword options:
        env<dict> = os.environ -- environment to execute program with
        cwd<str> = os.getcwd() -- directory to execute program  in
        shell<bool> = True -- whether to treat program as an argument to a shell, or a path to an executable
        newlines<bool> = True -- allow python to tamper with i/o to convert newlines
        show<bool> = False -- if within a windowed environment, open up a console for the process.
        paused<bool> = False -- if enabled, then don't start the process until .start() is called
        timeout<float> = -1 -- if positive, then raise a Asynchronous.Empty exception at the specified interval.
        """
        ## default properties
        self.__updater = None
        self.__threads = weakref.WeakSet()
        self.__kwds = kwds

        args = shlex.split(command) if isinstance(command, basestring) else command[:]
        command = args.pop(0)
        self.command = command, args[:]

        self.eventWorking = Asynchronous.Event()
        self.__taskQueue = Asynchronous.Queue()
        self.__exceptionQueue = Asynchronous.Queue()

        self.stdout = kwds.pop('stdout')
        self.stderr = kwds.pop('stderr')

        ## start the process
        not kwds.get('paused', False) and self.start()

    def start(self, **options):
        '''Start the command with the requested `options`.'''
        if self.running:
            raise OSError("Process {:d} is still running.".format(self.id))
        if self.updater or len(self.threads):
            raise OSError("Process {:d} management threads are still running.".format(self.id))

        ## copy our default options into a dictionary
        kwds = self.__kwds.copy()
        kwds.update(options)

        env = kwds.get('env', os.environ)
        cwd = kwds.get('cwd', os.getcwd())
        newlines = kwds.get('newlines', True)
        shell = kwds.get('shell', False)
        stdout, stderr = options.pop('stdout', self.stdout), options.pop('stderr', self.stderr)

        ## spawn our subprocess using our new outputs
        self.program = process.subprocess([self.command[0]] + self.command[1], cwd, env, newlines, joined=(stderr is None) or stdout == stderr, shell=shell, show=kwds.get('show', False))
        self.eventWorking.clear()

        ## monitor program's i/o
        self.__start_monitoring(stdout, stderr)
        self.__start_updater(timeout=kwds.get('timeout', -1))

        ## start monitoring
        self.eventWorking.set()
        return self

    def __start_updater(self, daemon=True, timeout=0):
        '''Start the updater thread. **used internally**'''

        ## define the closure that wraps our co-routines
        def task_exec(emit, data):
            if hasattr(emit, 'send'):
                res = emit.send(data)
                res and P.write(res)
            else: emit(data)

        ## define the closures that block on the specified timeout
        def task_get_timeout(P, timeout):
            try:
                emit, data = P.taskQueue.get(block=True, timeout=timeout)
            except Asynchronous.QueueEmptyException:
                _, _, tb = sys.exc_info()
                P.exceptionQueue.put(StopIteration, StopIteration(), tb)
                return ()
            return emit, data

        def task_get_notimeout(P, timeout):
            return P.taskQueue.get(block=True)
        task_get = task_get_timeout if timeout > 0 else task_get_notimeout

        ## define the closure that updates our queues and results
        def update(P, timeout):
            P.eventWorking.wait()
            while P.eventWorking.is_set():
                res = task_get(P, timeout)
                if not res: continue
                emit, data = res

                try:
                    task_exec(emit, data)
                except StopIteration:
                    P.eventWorking.clear()
                except:
                    P.exceptionQueue.put(sys.exc_info())
                finally:
                    hasattr(P.taskQueue, 'task_done') and P.taskQueue.task_done()
                continue
            return

        ## actually create and start our update threads
        self.__updater = updater = Asynchronous.Thread(target=update, name="thread-{:x}.update".format(self.id), args=(self, timeout))
        updater.daemon = daemon
        updater.start()
        return updater

    def __start_monitoring(self, stdout, stderr=None):
        '''Start monitoring threads. **used internally**'''
        name = "thread-{:x}".format(self.program.pid)

        ## create monitoring threads (coroutines)
        if stderr:
            res = process.monitorPipe(self.taskQueue, (stdout, self.program.stdout), (stderr, self.program.stderr), name=name)
        else:
            res = process.monitorPipe(self.taskQueue, (stdout, self.program.stdout), name=name)

        ## attach a friendly method that allows injection of data into the monitor
        res = map(None, res)
        for t, q in res: t.send = q.send
        threads, senders = zip(*res)

        ## update our set of threads for destruction later
        self.__threads.update(threads)

        ## set everything off
        for t in threads: t.start()

    @staticmethod
    def subprocess(program, cwd, environment, newlines, joined, shell=(os.name == 'nt'), show=False):
        '''Create a subprocess using Asynchronous.spawn.'''
        stderr = Asynchronous.spawn_options.STDOUT if joined else Asynchronous.spawn_options.PIPE

        ## collect our default options for calling Asynchronous.spawn (subprocess.Popen)
        options = dict(universal_newlines=newlines, stdin=Asynchronous.spawn_options.PIPE, stdout=Asynchronous.spawn_options.PIPE, stderr=stderr)
        if os.name == 'nt':
            options['startupinfo'] = si = Asynchronous.spawn_options.STARTUPINFO()
            si.dwFlags = Asynchronous.spawn_options.STARTF_USESHOWWINDOW
            si.wShowWindow = 0 if show else Asynchronous.spawn_options.SW_HIDE
            options['creationflags'] = cf = Asynchronous.spawn_options.CREATE_NEW_CONSOLE if show else 0
            options['close_fds'] = False
            options.update(dict(close_fds=False, startupinfo=si, creationflags=cf))
        else:
            options['close_fds'] = True
        options['cwd'] = cwd
        options['env'] = environment
        options['shell'] = shell

        ## split our arguments out if necessary
        command = shlex.split(program) if isinstance(program, basestring) else program[:]

        ## finally hand it off to subprocess.Popen
        try: return Asynchronous.spawn(command, **options)
        except OSError: raise OSError("Unable to execute command: \"{:s}\"".format(string.escape(command, '"')))

    @staticmethod
    def monitorPipe(q, (id, pipe), *more, **options):
        """Attach a coroutine to a monitoring thread for stuffing queue `q` with data read from `pipe`

        Yields a list of (thread, coro) tuples given the arguments provided.
        Each thread will read from `pipe`, and stuff the value combined with `id` into `q`.
        """
        def stuff(q, *key):
            while True: q.put(key + ((yield),))

        for id, pipe in itertools.chain([(id, pipe)], more):
            res, name = stuff(q, id), "{:s}<{!r}>".format(options.get('name', ''), id)
            yield process.monitor(res.next() or res.send, pipe, name=name), res
        return

    @staticmethod
    def monitor(send, pipe, blocksize=1, daemon=True, name=None):
        """Spawn a thread that reads `blocksize` bytes from `pipe` and dispatches it to `send`

        For every single byte, `send` is called. The thread is named according to
        the `name` parameter.

        Returns the monitoring Asynchronous.Thread instance
        """

        # FIXME: if we can make this asychronous on windows, then we can
        #        probably improve this significantly by either watching for
        #        a newline (newline buffering), or timing out if no data was
        #        received after a set period of time. so this way we can
        #        implement this in a lwt, and simply swap into and out-of
        #        shuffling mode.
        def shuffle(send, pipe):
            while not pipe.closed:
                # FIXME: would be nice if python devers implemented support for
                # reading asynchronously or a select.select from an anonymous pipe.
                data = pipe.read(blocksize)
                if len(data) == 0:
                    # pipe.read syscall was interrupted. so since we can't really
                    # determine why (cause...y'know..python), stop dancing so
                    # the parent will actually be able to terminate us
                    break
                map(send, data)
            return

        ## create our shuffling thread
        if name:
            truffle = Asynchronous.Thread(target=shuffle, name=name, args=(send, pipe))
        else:
            truffle = Asynchronous.Thread(target=shuffle, args=(send, pipe))

        ## ..and set its daemonicity
        truffle.daemon = daemon
        return truffle

    def __format_process_state(self):
        if self.program is None:
            return "Process \"{!r}\" {:s}.".format(self.command[0], 'was never started')
        res = self.program.poll()
        return "Process {:d} {:s}".format(self.id, 'is still running' if res is None else "has terminated with code {:d}".format(res))

    def write(self, data):
        '''Write `data` directly to program's stdin.'''
        if self.running and not self.program.stdin.closed:
            if self.updater and self.updater.is_alive():
                return self.program.stdin.write(data)
            raise IOError("Unable to write to stdin for process {:d}. Updater thread has prematurely terminated.".format(self.id))
        raise IOError("Unable to write to stdin for process. {:s}.".format(self.__format_process_state()))

    def close(self):
        '''Closes stdin of the program.'''
        if self.running and not self.program.stdin.closed:
            return self.program.stdin.close()
        raise IOError("Unable to close stdin for process. {:s}.".format(self.__format_process_state()))

    def signal(self, signal):
        '''Raise a signal to the program.'''
        if self.running:
            return self.program.send_signal(signal)
        raise IOError("Unable to raise signal {!r} to process. {:s}.".format(signal, self.__format_process_state()))

    def exception(self):
        '''Grab an exception if there's any in the queue.'''
        if self.exceptionQueue.empty(): return
        res = self.exceptionQueue.get()
        hasattr(self.exceptionQueue, 'task_done') and self.exceptionQueue.task_done()
        return res

    def wait(self, timeout=0.0):
        '''Wait a given amount of time for the process to terminate.'''
        if self.program is None:
            raise RuntimeError("Program '{:s}' is not running.".format(string.escape(self.command[0], '\'')))

        ## if we're not running, then return the result that we already received
        if not self.running:
            return self.program.returncode

        self.updater.is_alive() and self.eventWorking.wait()

        ## spin the cpu until we timeout
        if timeout:
            t = time.time()
            while self.running and self.eventWorking.is_set() and time.time() - t < timeout:
                if not self.exceptionQueue.empty():
                    res = self.exception()
                    raise res[0], res[1], res[2]
                continue
            return self.program.returncode if self.eventWorking.is_set() else self.__terminate()

        ## return the program's result

        # XXX: doesn't work correctly with PIPEs due to pythonic programmers' inability to understand os semantics

        while self.running and self.eventWorking.is_set():
            if not self.exceptionQueue.empty():
                res = self.exception()
                raise res[0], res[1], res[2]
            continue    # ugh...poll-forever (and kill-cpu) until program terminates...

        if not self.eventWorking.is_set():
            return self.__terminate()
        return self.program.returncode

    def stop(self):
        self.eventWorking.clear()
        return self.__terminate()

    def __terminate(self):
        '''Sends a SIGKILL signal and then waits for program to complete.'''
        pid = self.program.pid
        try:
            self.program.kill()
        except OSError, e:
            logger.fatal("{:s}.__terminate : Exception {!r} was raised while trying to kill process {:d}. Terminating its management threads regardless.".format('.'.join((__name__, self.__class__.__name__)), e, pid), exc_info=True)
        finally:
            while self.running: continue

        self.__stop_monitoring()
        if self.exceptionQueue.empty():
            return self.program.returncode

        res = self.exception()
        raise res[0], res[1], res[2]

    def __stop_monitoring(self):
        '''Cleanup monitoring threads.'''
        P = self.program
        if P.poll() is None:
            raise RuntimeError("Unable to stop monitoring while process {!r} is still running.".format(P))

        ## stop the update thread
        self.eventWorking.clear()

        ## forcefully close pipes that still open (this should terminate the monitor threads)

        # also, this fixes a resource leak since python doesn't do this on subprocess death
        for p in (P.stdin, P.stdout, P.stderr):
            while p and not p.closed:
                try: p.close()
                except: pass
            continue

        ## join all monitoring threads

        # XXX: when cleaning up, this module disappears despite there still
        #      being a reference for some reason
        import operator

        # XXX: there should be a better way to block until all threads have joined
        map(operator.methodcaller('join'), self.threads)

        # now spin until none of them are alive
        while len(self.threads) > 0:
            for th in self.threads[:]:
                if not th.is_alive(): self.__threads.discard(th)
                del(th)
            continue

        ## join the updater thread, and then remove it
        self.taskQueue.put(None)
        self.updater.join()
        if self.updater.is_alive():
            raise AssertionError
        self.__updater = None
        return

    def __repr__(self):
        ok = self.exceptionQueue.empty()
        state = "running pid:{:d}".format(self.id) if self.running else "stopped cmd:{!r}".format(self.command[0])
        threads = [
            ('updater', 0 if self.updater is None else self.updater.is_alive()),
            ('input/output', len(self.threads))
        ]
        return "<process {:s}{:s} threads{{{:s}}}>".format(state, (' !exception!' if not ok else ''), ' '.join("{:s}:{:d}".format(n, v) for n, v in threads))

## interface for wrapping the process class
def spawn(stdout, command, **options):
    """Spawn `command` with the specified `**options`.

    If program writes anything to stdout, dispatch it to the `stdout` callable.
    If `stderr` is defined, call `stderr` with anything written to the program's stderr.
    """
    # grab arguments that we care about
    stderr = options.pop('stderr', None)
    daemon = options.pop('daemon', True)

    # empty out the first generator result if a coroutine is passed
    if hasattr(stdout, 'send'):
        res = stdout.next()
        res and P.write(res)
    if hasattr(stderr, 'send'):
        res = stderr.next()
        res and P.write(res)

    # spawn the sub-process
    return process(command, stdout=stdout, stderr=stderr, **options)

### execution scheduler
import threading, multiprocessing, Queue

# we use "multiprocessing" locks because they use straight-up and simple
# platform-specific semaphores instead of python's stupid and unstable BGL
# used by everything in "threading". i'm not trying to share my precious
# (time-)slices with you, Python.

# FIXME: using this result queue is a horrible way to get results.
#        instead it'd be nice to expose a promise-like paradigm and
#        also expose a way to directly re-prioritize the scheduler's
#        execution queue based on which promises are checked the most
#        often or being directly blocked on. (heapq or queue.PriorityQueue)
class execution(object):
    __slots__ = ('queue', 'state', 'result', 'ev_unpaused', 'ev_terminating')
    __slots__+= ('thread', 'lock')

    running = property(fget=lambda self: self.thread.is_alive() and self.ev_unpaused.is_set() and not s.ev_terminating.is_set())
    dead = property(fget=lambda self: self.thread.is_alive())

    def __init__(self):
        '''Execute a function asynchronously in another thread.'''

        ## management of the current execution queue
        res = multiprocessing.Lock()
        self.queue = multiprocessing.Condition(res)
        self.state = []

        ## queue of results from successful tasks

        # the data in this queue is shared with the main python thread,
        # so it's okay to use Python's giant lock here.
        self.result = Queue.Queue()

        ## thread-based task scheduler
        self.ev_unpaused = multiprocessing.Event()
        self.ev_terminating = multiprocessing.Event()
        self.thread = threading.Thread(target=self.__run__, name="Thread-{:s}-{:x}".format(self.__class__.__name__, id(self)))

        # FIXME: we _can_ support multiple threads, but this is all being
        #        bound by a single lock due to my distrust for IDAPython.
        #        it _does_ seem to run Python stuff in its own thread, but
        #        i don't have faith in that they're grabbing Python's huge
        #        lock during all idaapi calls.
        self.lock = multiprocessing.Lock()

        ## start our task scheduler
        return self.__start()

    def release(self):
        '''Empty out all the tasks and release all the resources required to execute them.'''
        self.queue.acquire()
        self.state = []
        self.queue.release()
        return self.__stop()

    def __del__(self):
        self.release()

    def __repr__(self):
        cls = self.__class__
        state = 'paused'
        if self.ev_unpaused.is_set():
            state = 'running'
        if self.ev_terminating.is_set():
            state = 'terminated'
        if not self.thread.is_alive():
            state = 'dead'
        res = tuple(self.state)
        return "<class '{:s}'> {:s} Queue:{:d} Results:{:d}".format('.'.join(('internal', __name__, cls.__name__)), state, len(res), self.result.unfinished_tasks)  # XXX

    def notify(self):
        '''Notify the execution queue that it should process anything that is queued.'''
        logging.debug(u"{:s}.notify() : Waking up execution queue {!r}.".format('.'.join(('internal', __name__, cls.__name__)), self))
        self.queue.acquire()
        self.queue.notify()
        self.queue.release()

    def next(self):
        '''Notify the execution queue that a result is needed, and then block until we can return the next one that's available.'''
        self.queue.acquire()
        while self.state:
            self.queue.notify()
        self.queue.release()

        if self.result.empty():
            raise StopIteration
        return self.pop()

    def __start(self):
        cls = self.__class__
        logging.debug(u"{:s}.start() : Starting execution scheduler {!r}.".format('.'.join(('internal', __name__, cls.__name__)), self.thread))
        self.ev_terminating.clear(), self.ev_unpaused.set()
        self.thread.daemon = True
        return self.thread.start()

    def __stop(self):
        cls = self.__class__
        logging.debug(u"{:s}.stop() : Terminating execution scheduler {!r}.".format('.'.join(('internal', __name__, cls.__name__)), self.thread))
        if not self.thread.is_alive():
            cls = self.__class__
            logging.warn(u"{:s}.stop() : Execution scheduler has already been terminated as {!r}.".format('.'.join(('internal', __name__, cls.__name__)), self))
            return
        self.ev_unpaused.set(), self.ev_terminating.set()
        self.queue.acquire()
        self.queue.notify_all()
        self.queue.release()
        return self.thread.join()

    def start(self):
        '''Start to dispatch callables in the execution queue.'''
        cls = self.__class__
        if not self.thread.is_alive():
            logging.fatal(u"{:s}.start() : Unable to resume an already terminated execution scheduler {!r}.".format('.'.join(('internal', __name__, cls.__name__)), self))
            return False
        logging.info(u"{:s}.start() : Resuming the execution scheduler {!r}.".format('.'.join(('internal', __name__, cls.__name__)), self.thread))
        res, _ = self.ev_unpaused.is_set(), self.ev_unpaused.set()
        self.queue.acquire()
        self.queue.notify_all()
        self.queue.release()
        return not res

    def stop(self):
        '''Pause the execution scheduler.'''
        cls = self.__class__
        if not self.thread.is_alive():
            logging.fatal(u"{:s}.stop() : Unable to pause the execution scheduler {!r} as it has already been terminated.".format('.'.join(('internal', __name__, cls.__name__)), self))
            return False
        logging.info(u"{:s}.stop() : Pausing execution scheduler {!r}.".format('.'.join(('internal', __name__, cls.__name__)), self.thread))
        res, _ = self.ev_unpaused.is_set(), self.ev_unpaused.clear()
        self.queue.acquire()
        self.queue.notify_all()
        self.queue.release()
        return res

    def push(self, F, *args, **kwds):
        '''Push `F` with the provided `args` and `kwds` onto the execution queue.'''
        # package it all into a single function
        res = functools.partial(F, *args, **kwds)

        cls = self.__class__
        logging.debug(u"{:s}.push(...) : Adding the callable {!r} to the execution scheduler's queue {!r}.".format('.'.join(('internal', __name__, cls.__name__)), F, self))
        # shove it down a multiprocessing.Queue
        self.queue.acquire()
        self.state.append(res)
        self.queue.notify()
        self.queue.release()
        return True

    def pop(self):
        '''Pop a result off of the result queue.'''
        cls = self.__class__
        if not self.thread.is_alive():
            logging.fatal(u"{:s}.pop() : Refusing to wait for a result when execution scheduler has already terminated. Execution queue is currently {!r}.".format('.'.join(('internal', __name__, cls.__name__)), self))
            raise Queue.Empty

        logging.debug(u"{:s}.pop() : Popping result off of the execution scheduler's result queue {!r}.".format('.'.join(('internal', __name__, cls.__name__)), self))
        try:
            _, res, err = self.result.get(block=0)
            if err != (None, None, None):
                t, e, tb = err
                raise t, e, tb
        finally:
            self.result.task_done()
        return res

    @classmethod
    def __consume(cls, event, queue, state):
        while True:
            if event.is_set():
                break
            queue.wait()
            if state: yield state.pop(0)
        yield   # prevents us from having to catch a StopIteration

    @classmethod
    def __dispatch(cls, lock):
        res, error = None, (None, None, None)
        while True:
            F = (yield res, error)
            lock.acquire()
            try:
                res = F()
            except:
                res, error = None, sys.exc_info()
            else:
                error = None, None, None
            finally: lock.release()
        return

    def __run__(self):
        cls = self.__class__
        consumer = self.__consume(self.ev_terminating, self.queue, self.state)
        executor = self.__dispatch(self.lock); next(executor)

        logging.debug(u"{:s}.thread({!r}) : The execution scheduler's thread is now running.".format('.'.join(('internal', __name__, cls.__name__)), self.thread))
        while not self.ev_terminating.is_set():
            # check if we're allowed to execute
            if not self.ev_unpaused.is_set():
                self.ev_unpaused.wait()

            # pull a callable out of the queue
            logging.debug(u"{:s}.thread({!r}) : Waiting for an item from scheduler.".format('.'.join(('internal', __name__, cls.__name__)), self.thread))
            self.queue.acquire()
            item = next(consumer)
            self.queue.release()

            if not self.ev_unpaused.is_set():
                self.ev_unpaused.wait()

            # check if we're terminating
            if self.ev_terminating.is_set(): break

            # now we can execute it
            logging.debug(u"{:s}.thread({!r}) : Item {!r} has been scheduled asynchronously on thread.".format('.'.join(('internal', __name__, cls.__name__)), self.thread, item))
            res, err = executor.send(item)

            # and stash our result
            logging.debug(u"{:s}.thread({!r}) : Scheduler received result {!r} for item {!r}.".format('.'.join(('internal', __name__, cls.__name__)), self.thread, (res, err), item))
            self.result.put((item, res, err))
        return

### matcher class helper

# FIXME: figure out how to match against a bounds_t in a non-hacky way
class matcher(object):
    """
    An object that allows one to match or filter a list of things in an
    sort of elegant way.
    """

    def __init__(self):
        self.__predicate__ = {}
    def __attrib__(self, *attribute):
        if not attribute:
            return lambda n: n
        res = [(operator.attrgetter(a) if isinstance(a, basestring) else a) for a in attribute]
        return lambda o: tuple(x(o) for x in res) if len(res) > 1 else res[0](o)
    def attribute(self, type, *attribute):
        attr = self.__attrib__(*attribute)
        self.__predicate__[type] = lambda v: fcompose(attr, functools.partial(functools.partial(operator.eq, v)))
    def mapping(self, type, function, *attribute):
        attr = self.__attrib__(*attribute)
        mapper = fcompose(attr, function)
        self.__predicate__[type] = lambda v: fcompose(mapper, functools.partial(operator.eq, v))
    def boolean(self, type, function, *attribute):
        attr = self.__attrib__(*attribute)
        self.__predicate__[type] = lambda v: fcompose(attr, functools.partial(function, v))
    def predicate(self, type, *attribute):
        attr = self.__attrib__(*attribute)
        self.__predicate__[type] = functools.partial(fcompose, attr)
    def match(self, type, value, iterable):
        matcher = self.__predicate__[type](value)
        return itertools.ifilter(matcher, iterable)

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

        backslash = '\\'

        # character mappings to escaped versions
        mappings = {
            '\a' : r'\a',
            '\b' : r'\b',
            '\t' : r'\t',
            '\n' : r'\n',
            '\v' : r'\v',
            '\f' : r'\f',
            '\r' : r'\r',
            '\0' : r'\0',
            '\1' : r'\1',
            '\2' : r'\2',
            '\3' : r'\3',
            '\4' : r'\4',
            '\5' : r'\5',
            '\6' : r'\6',
            # '\7' : r'\7',     # this is the same as '\a'
        }

        # inverse mappings of characters plus the '\7 -> '\a' byte
        inverse = { v : k for k, v in itertools.chain([('\7', r'\7')], six.iteritems(mappings)) }

        # whitespace characters as a set
        whitespace = { ch for ch in _string.whitespace }

        # printable characters as a set
        printable = { ch for ch in _string.printable } - whitespace

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
        if integer >= 0 and integer < 0x10:
            return six.int2byte(integer + 0x30) if integer < 10 else six.int2byte(integer + 0x57)
        raise ValueError

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
            n = six.byte2int(ch)

            # check if character has an existing escape mapping
            if cls.mapQ(ch):
                for ch in cls.map(ch):
                    result.send(ch)

            # check if character is printable (unicode)
            elif isinstance(ch, unicode) and cls.unicodeQ(ch):
                result.send(ch)

            # check if character is printable (ascii)
            elif isinstance(ch, str) and cls.asciiQ(ch):
                result.send(ch)

            # check if character is a single-byte ascii
            elif n < 0x100:
                result.send(cls.const.backslash)
                result.send('x')
                result.send(cls.to_hex((n & 0xf0) / 0x10))
                result.send(cls.to_hex((n & 0x0f) / 0x01))

            # check that character is an unprintable unicode character
            elif n < 0x10000:
                result.send(cls.const.backslash)
                result.send('u')
                result.send(cls.to_hex((n & 0xf000) / 0x1000))
                result.send(cls.to_hex((n & 0x0f00) / 0x0100))
                result.send(cls.to_hex((n & 0x00f0) / 0x0010))
                result.send(cls.to_hex((n & 0x000f) / 0x0001))

            # maybe the character is an unprintable long-unicode character
            elif n < 0x110000:
                result.send(cls.const.backslash)
                result.send('U')
                result.send(cls.to_hex((n & 0x100000) / 0x100000))
                result.send(cls.to_hex((n & 0x0f0000) / 0x010000))
                result.send(cls.to_hex((n & 0x00f000) / 0x001000))
                result.send(cls.to_hex((n & 0x000f00) / 0x000100))
                result.send(cls.to_hex((n & 0x0000f0) / 0x000010))
                result.send(cls.to_hex((n & 0x00000f) / 0x000001))

            # if we're here, then we have no idea what kind of character it is
            else:
                raise internal.exceptions.InvalidFormatError(u"{:s}.unescape({!s}) : Unable to determine how to escape the current character code ({:#x}).".format('.'.join(('internal', __name__, cls.__name__)), iterable, n))

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

                # check if the 'x' prefix is specified, which represents a hex digit
                elif t == 'x':
                    hb, lb = (yield), (yield)
                    if any(not cls.hexQ(b) for b in {hb, lb}):
                        raise internal.exceptions.InvalidFormatError(u"{:s}.unescape({!s}) : Expected the next two characters ('{:s}', '{:s}') to be hex digits for an ascii character.".format('.'.join(('internal', __name__, cls.__name__)), result, internal.interface.string.escape(hb, '\''), internal.interface.string.escape(lb, '\'')))

                    # convert the two hex digits into their integral forms
                    h, l = map(cls.of_hex, (hb.lower(), lb.lower()))

                    # coerce the digits into an ascii character and send the character to our result
                    result.send(six.int2byte(
                        h * 0x10 |
                        l * 0x01 |
                    0))

                # if we find a 'u' prefix, then we have a unicode character
                elif t == 'u':
                    hwb, lwb, hb, lb = (yield), (yield), (yield), (yield)
                    if any(not cls.hexQ(b) for b in {hwb, lwb, hb, lb}):
                        raise internal.exceptions.InvalidFormatError(u"{:s}.unescape({!s}) : Expected the next four characters ('{:s}', '{:s}', '{:s}', '{:s}') to be hex digits for a unicode character.".format('.'.join(('internal', __name__, cls.__name__)), result, internal.interface.string.escape(hwb, '\''), internal.interface.string.escape(lwb, '\''), internal.interface.string.escape(hb, '\''), internal.interface.string.escape(lb, '\'')))

                    # convert the four hex digits into their integral forms
                    hw, lw, h, l = map(cls.of_hex, (hwb.lower(), lwb.lower(), hb.lower(), lb.lower()))

                    # coerce the digits into a unicode character and send the character to our result
                    result.send(six.unichr(
                        hw * 0x1000 |
                        lw * 0x0100 |
                        h  * 0x0010 |
                        l  * 0x0001 |
                    0))

                # if we find a 'U' prefix, then we have a long unicode character
                elif t == 'U':
                    Hwb, Lwb, hwb, lwb, hb, lb = (yield), (yield), (yield), (yield), (yield), (yield)
                    if any(not cls.hexQ(b) for b in {Hwb, Lwb, hwb, lwb, hb, lb}) or Hwb not in {'0', '1'}:
                        raise internal.exceptions.InvalidFormatError(u"{:s}.unescape({!s}) : Expected the next six characters ('{:s}', '{:s}', '{:s}', '{:s}', '{:s}', '{:s}') to be hex digits for a long-unicode character.".format('.'.join(('internal', __name__, cls.__name__)), result, internal.interface.string.escape(Hwb, '\''), internal.interface.string.escape(Lwb, '\''), internal.interface.string.escape(hwb, '\''), internal.interface.string.escape(lwb, '\''), internal.interface.string.escape(hb, '\''), internal.interface.string.escape(lb, '\'')))

                    # convert the six hex digits into their integral forms
                    Hw, Lw, hw, lw, h, l = map(cls.of_hex, (Hwb.lower(), Lwb.lower(), hwb.lower(), lwb.lower(), hb.lower(), lb.lower()))

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
                    raise internal.exceptions.InvalidFormatError(u"{:s}.unescape({!s}) : An unknown character code was specified ('{:s}').".format('.'.join(('internal', __name__, cls.__name__)), result, internal.interface.string.escape(t, '\'')))

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
    def of(cls, string):
        '''Return a string from IDA in a format that is consistent'''
        return None if string is None else string.decode('utf8') if isinstance(string, str) else string

    @classmethod
    def to(cls, string):
        '''Convert a string into a form that IDA will accept.'''
        return None if string is None else string.encode('utf8') if isinstance(string, unicode) else string

    # dictionary for mapping control characters to their correct forms
    mapping = {
        '\n' : r'\n',
         ' ' : r' ',
    }

    @classmethod
    def escape(cls, string, quote=''):
        """Escape the characters in `string` specified by `quote`.

        Handles both unicode and ascii. Defaults to escaping only
        the unprintable characters.
        """

        # construct a list for anything that gets transformed
        res = internal.interface.collect_t(list, lambda agg, value: agg + [value])

        # instantiate our generator for escaping unprintables in the string
        transform = character.escape(res); next(transform)

        # iterate through each character, sending everything to res
        for ch in iter(string):

            # check if character is a user-specified quote or a backslash
            if any(operator.contains(set, ch) for set in (quote, '\\')):
                res.send('\\')
                res.send(ch)

            # check if character has an escape mapping to use
            elif operator.contains(cls.mapping, ch):
                map(res.send, cls.mapping[ch])

            # otherwise we can just send it to transform to escape it
            else:
                transform.send(ch)
            continue

        # figure out the correct function that determines how to join the res
        fjoin = (unicode() if isinstance(string, unicode) else str()).join

        return fjoin(res.get())

    @classmethod
    def repr(cls, item):
        """Given an item, return the `repr()` of it whilst ensuring that a proper ascii string is returned.

        All unicode strings are encoded to UTF-8 in order to guarantee
        the resulting string can be emitted.
        """
        if isinstance(item, basestring):
            res = cls.escape(item, '\'')
            if all(six.byte2int(ch) < 0x100 for ch in item):
                return "'{:s}'".format(res)
            return u"u'{:s}'".format(res)
        elif isinstance(item, tuple):
            res = map(cls.repr, item)
            return "({:s}{:s})".format(', '.join(res), ',' if len(item) == 1 else '')
        elif isinstance(item, list):
            res = map(cls.repr, item)
            return "[{:s}]".format(', '.join(res))
        elif isinstance(item, set):
            res = map(cls.repr, item)
            return "set([{:s}])".format(', '.join(res))
        elif isinstance(item, dict):
            res = ("{:s}: {:s}".format(cls.repr(k), cls.repr(v)) for k, v in six.iteritems(item))
            return "{{{:s}}}".format(', '.join(res))
        return repr(item)

    @classmethod
    def kwargs(cls, kwds):
        '''Format a dictionary (from kwargs) so that it can be emitted to a user as part of a message.'''
        res = []
        for key, value in six.iteritems(kwds):
            k, v = cls.escape(key), cls.repr(value)
            res.append("{:s}={!s}".format(k.encode('utf8'), v))
        return ', '.join(res).decode('utf8')

### wrapping functions with another caller whilst preserving the wrapped function
class wrap(object):
    """
    A lot of magic is in this class which allows one to do a proper wrap
    around a single callable.
    """

    CO_OPTIMIZED                = 0x00001
    CO_NEWLOCALS                = 0x00002
    CO_VARARGS                  = 0x00004
    CO_VARKEYWORDS              = 0x00008
    CO_NESTED                   = 0x00010
    CO_VARGEN                   = 0x00020
    CO_NOFREE                   = 0x00040
    CO_COROUTINE                = 0x00080
    CO_ITERABLE                 = 0x00100
    CO_GENERATOR_ALLOWED        = 0x01000
    CO_FUTURE_DIVISION          = 0x02000
    CO_FUTURE_ABSOLUTE_IMPORT   = 0x04000
    CO_FUTURE_WITH_STATEMENT    = 0x08000
    CO_FUTURE_PRINT_FUNCTION    = 0x10000
    CO_FUTURE_UNICODE_LITERALS  = 0x20000
    CO_FUTURE_BARRY_AS_BDFL     = 0x40000
    CO_FUTURE_GENERATOR_STOP    = 0x80000

    import opcode, compiler.consts as consts

    @classmethod
    def co_assemble(cls, operation, operand=None):
        '''Assembles the specified `operation` and `operand` into a code string.'''
        opcode = cls.opcode.opmap[operation]
        if operand is None:
            return six.int2byte(opcode)

        # if operand was defined, then encode it
        op1 = (operand & 0x00ff) / 0x0001
        op2 = (operand & 0xff00) / 0x0100
        return reduce(operator.add, map(six.int2byte, (opcode, op1, op2)), bytes())

    @classmethod
    def co_varargsQ(cls, co):
        '''Returns whether the provided code type, `co`, takes variable arguments.'''
        return bool(co.co_flags & cls.consts.CO_VARARGS)

    @classmethod
    def co_varkeywordsQ(cls, co):
        '''Returns whether the provided code type, `co`, takes variable keyword arguments.'''
        return bool(co.co_flags & cls.consts.CO_VARKEYWORDS)

    @classmethod
    def cell(cls, *args):
        '''Convert `args` into a ``cell`` tuple.'''
        return tuple(((lambda item: lambda : item)(arg).func_closure[0]) for arg in args)

    @classmethod
    def assemble(cls, function, wrapper, bound=False):
        """Assemble a ``types.CodeType`` that will execute `wrapper` with `F` as its first parameter.

        If `bound` is ``True``, then assume that the first parameter for `F` represents the instance it's bound to.
        """
        F, C, S = map(cls.extract, (function, wrapper, cls.assemble))
        Fc, Cc, Sc = map(operator.attrgetter('func_code'), (F, C, S))

        ## build the namespaces that we'll use
        Tc = cls.co_varargsQ(Fc), cls.co_varkeywordsQ(Fc)

        # first we'll build the globals that get passed to the wrapper
        Sargs = ('F', 'wrapper')
        Svals = (f if callable(f) else fo for f, fo in [(function, F), (wrapper, C)])

        # rip out the arguments from our target `F`
        Fargs = Fc.co_varnames[:Fc.co_argcount]
        Fwildargs = Fc.co_varnames[Fc.co_argcount : Fc.co_argcount + sum(Tc)]

        # combine them into tuples for looking up variables
        co_names, co_varnames = Sargs[:], Fargs[:] + Fwildargs[:]

        # free variables (that get passed to `C`)
        co_freevars = Sargs[:2]

        # constants for code type (which consist of just the self-doc)
        co_consts = (F.func_doc,)

        ## figure out some things for assembling the bytecode

        # first we'll grab the call instruction type to use
        call_ = {
            (False, False) : 'CALL_FUNCTION',
            (True, False)  : 'CALL_FUNCTION_VAR',
            (False, True)  : 'CALL_FUNCTION_KW',
            (True, True)   : 'CALL_FUNCTION_VAR_KW',
        }
        call = call_[Tc]

        # now we'll determine the flags to apply
        flags_ = {
            (False, False) : 0,
            (True, False)  : cls.CO_VARARGS,
            (False, True)  : cls.CO_VARKEYWORDS,
            (True, True)   : cls.CO_VARARGS | cls.CO_VARKEYWORDS
        }

        co_flags = cls.CO_NESTED | cls.CO_OPTIMIZED | cls.CO_NEWLOCALS | flags_[Tc]

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

        # call `wrapper` with the correct call type (+1 for `F`, -1 if bound)
        asm(cls.co_assemble(call, len(Fargs) + 1 - int(bound)))

        # and then return its value
        asm(cls.co_assemble('RETURN_VALUE'))

        # combine it into a single code string
        co_code = bytes().join(code_)

        ## next we'll construct the code type based on what we have
        cargs = len(Fargs), len(co_names) + len(co_varnames) + len(co_freevars), \
                co_stacksize, co_flags, co_code, \
                co_consts, co_names, co_varnames, \
                Fc.co_filename, Fc.co_name, Fc.co_firstlineno, \
                bytes(), co_freevars

        func_code = types.CodeType(*cargs)

        ## and then turn it back into a function
        res = types.FunctionType(func_code, F.func_globals, F.func_name, F.func_defaults, cls.cell(*Svals))
        res.func_name, res.func_doc = F.func_name, F.func_doc

        return res

    def __new__(cls, callable, wrapper):
        '''Return a function similar to `callable` that calls `wrapper` with `callable` as the first argument.'''
        cons, f = cls.constructor(callable), cls.extract(callable)

        # create a wrapper for the function that'll execute `callable` with the function as its first argument, and the rest with any args
        res = cls.assemble(callable, wrapper, bound=isinstance(callable, (classmethod, types.MethodType)))
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
            return object.im_func

        # if it's a code type, then walk through all of its referrers finding one that matches it
        elif isinstance(object, types.CodeType):
            res, = (n for n in gc.get_referrers(c) if n.func_name == c.co_name and isinstance(n, types.FunctionType))
            return res

        # if it's a property decorator, then they hide the function in an attribute
        elif isinstance(object, (staticmethod, classmethod)):
            return object.__func__

        # okay, no go. we have no idea what this is.
        raise internal.exceptions.InvalidTypeOrValueError(object)

    @classmethod
    def arguments(cls, f):
        '''Extract the arguments from a function `f`.'''
        c = f.func_code
        varnames_count, varnames_iter = c.co_argcount, iter(c.co_varnames)
        args = tuple(itertools.islice(varnames_iter, varnames_count))
        res = { a : v for v, a in zip(reversed(f.func_defaults or []), reversed(args)) }
        starargs = next(varnames_iter, '') if c.co_flags & cls.CO_VARARGS else ''
        kwdargs = next(varnames_iter, '') if c.co_flags & cls.CO_VARKEYWORDS else ''
        return args, res, (starargs, kwdargs)

    @classmethod
    def constructor(cls, callable):
        '''Return a closure that constructs the original `callable` type from a function.'''

        # `callable` is a function type, so just return a closure that returns it
        if isinstance(callable, types.FunctionType):
            return lambda func: func

        # if it's a method type, then we just need to extract the related properties to construct it
        elif isinstance(callable, types.MethodType):
            return lambda method, self=callable.im_self, cls=callable.im_class: types.MethodType(method, self, cls)

        # if it's a property decorator, we just need to pass the function as an argument to the decorator
        elif isinstance(callable, (staticmethod, classmethod)):
            return lambda method, mt=callable.__class__: mt(method)

        # if it's a method instance, then we just need to instantiate it so that it's bound
        elif isinstance(callable, types.InstanceType):
            return lambda method, mt=callable.__class__: types.InstanceType(mt, dict(method.__dict__))

        # otherwise if it's a class or a type, then we just need to create the object with its bases
        elif isinstance(n, (types.TypeType, types.ClassType)):
            return lambda method, t=callable.__class__, name=callable.__name__, bases=callable.__bases__: t(name, bases, dict(method.__dict__))

        # if we get here, then we have no idea what kind of type `callable` is
        raise internal.exceptions.InvalidTypeOrValueError(callable.__class__)

### function decorator for translating arguments belonging to a function
def transform(translate, *names):
    '''This applies the callable `translate` to any function arguments that match `names` in the decorated function.'''
    names = {name for name in names}
    def wrapper(F, *rargs, **rkwds):
        f = wrap.extract(F)
        argnames, defaults, _ = wrap.arguments(f)

        # convert any positional arguments
        res = ()
        for value, argname in zip(rargs, argnames):
            res += (translate(value) if argname in names else value),

        for value in rargs[len(res):]:
            res += (value,)

        # convert any keywords arguments
        kwds = dict(rkwds)
        for argname in six.viewkeys(rkwds) & names:
            kwds[argname] = kwds[argname].decode('utf8')
        return F(*res, **kwds)

    # decorater that wraps the function `F` with `wrapper`.
    def result(F):
        return wrap(F, wrapper)
    return result

