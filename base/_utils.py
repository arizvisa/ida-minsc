import __builtin__
import logging,sys,weakref
import itertools,operator,functools
import six,types,heapq,collections

import multiprocessing,Queue
import idaapi

__all__ = ['fbox','fboxed','box','boxed','funbox','unbox','finstance','fconstant','fpassthru','fpass','fidentity','fid','first','second','third','last','fcompose','compose','fdiscard','fcondition','fmaplist','fap','flazy','fmemo','fpartial','partial','fapply','fcurry','frpartial','freversed','frev','fexc','fexception','fcatch','fcomplement','fnot','ilist','liter','ituple','titer','itake','iget','imap','ifilter']

### functional programming primitives (FIXME: probably better to document these with examples)

# box any specified arguments
fbox = fboxed = box = boxed = lambda *a: a
# return a closure that executes ``f`` with the arguments unboxed.
funbox = unbox = lambda f, *a, **k: lambda *ap, **kp: f(*(a + __builtin__.reduce(operator.add, __builtin__.map(__builtin__.tuple, ap), ())), **__builtin__.dict(k.items() + kp.items()))
# return a closure that will check that ``object`` is an instance of ``type``.
finstance = lambda type: lambda object: isinstance(object, type)
# return a closure that always returns ``object``.
fconstant = fconst = falways = always = lambda object: lambda *a, **k: object
# a closure that returns its argument
fpassthru = fpass = fidentity = fid = lambda object: object
# return the first, second, or third item of a box.
first, second, third, last = operator.itemgetter(0), operator.itemgetter(1), operator.itemgetter(2), operator.itemgetter(-1)
# return a closure that executes a list of functions one after another from left-to-right
fcompose = compose = lambda *f: __builtin__.reduce(lambda f1, f2: lambda *a: f1(f2(*a)), __builtin__.reversed(f))
# return a closure that executes function ``f`` whilst discarding any extra arguments
fdiscard = lambda f: lambda *a, **k: f()
# return a closure that executes function ``crit`` and then executes ``f`` or ``t`` based on whether or not it's successful.
fcondition = fcond = lambda crit: lambda t, f: \
    lambda *a, **k: t(*a, **k) if crit(*a, **k) else f(*a, **k)
# return a closure that takes a list of functions to execute with the provided arguments
fmaplist = fap = lambda *fa: lambda *a, **k: (f(*a, **k) for f in fa)
#lazy = lambda f, state={}: lambda *a, **k: state[(f, a, __builtin__.tuple(__builtin__.sorted(k.items())))] if (f, a, __builtin__.tuple(__builtin__.sorted(k.items()))) in state else state.setdefault((f, a, __builtin__.tuple(__builtin__.sorted(k.items()))), f(*a, **k))
#lazy = lambda f, *a, **k: lambda *ap, **kp: f(*(a+ap), **dict(k.items() + kp.items()))
# return a memoized closure that's lazy and only executes when evaluated
def flazy(f, *a, **k):
    sortedtuple, state = fcompose(__builtin__.sorted, __builtin__.tuple), {}
    def lazy(*ap, **kp):
        A, K = a+ap, sortedtuple(k.items() + kp.items())
        return state[(A, K)] if (A, K) in state else state.setdefault((A, K), f(*A, **__builtin__.dict(k.items()+kp.items())))
    return lazy
fmemo = flazy
# return a closure with the function's arglist partially applied
fpartial = partial = functools.partial
# return a closure that applies the provided arguments to the function ``f``.
fapply = lambda f, *a, **k: lambda *ap, **kp: f(*(a+ap), **__builtin__.dict(k.items() + kp.items()))
# return a closure that will use the specified arguments to call the provided function.
fcurry = lambda *a, **k: lambda f, *ap, **kp: f(*(a+ap), **__builtin__.dict(k.items() + kp.items()))
# return a closure that applies the initial arglist to the end of function ``f``.
frpartial = lambda f, *a, **k: lambda *ap, **kp: f(*(ap + __builtin__.tuple(__builtin__.reversed(a))), **__builtin__.dict(k.items() + kp.items()))
# return a closure that applies the arglist to function ``f`` in reverse.
freversed = frev = lambda f, *a, **k: lambda *ap, **kp: f(*__builtin__.reversed(a + ap), **__builtin__.dict(k.items() + kp.items()))
# return a closure that executes function ``f`` and includes the caught exception (or None) as the first element in the boxed result.
def fcatch(f, *a, **k):
    def fcatch(*a, **k):
        try: return __builtin__.None, f(*a, **k)
        except: return sys.exc_info()[1], __builtin__.None
    return functools.partial(fcatch, *a, **k)
fexc = fexception = fcatch
# boolean inversion of the result of a function
fcomplement = fnot = complement = frpartial(fcompose, operator.not_)
# converts a list to an iterator, or an iterator to a list
ilist, liter = compose(list, iter), compose(iter, list)
# converts a tuple to an iterator, or an iterator to a tuple
ituple, titer = compose(tuple, iter), compose(iter, tuple)
# take ``count`` number of elements from an iterator
itake = lambda count: compose(iter, fap(*(next,)*count), tuple)
# get the ``nth`` element from an iterator
iget = lambda count: compose(iter, fap(*(next,)*(count)), tuple, operator.itemgetter(-1))
# copy from itertools
imap, ifilter = itertools.imap, itertools.ifilter

# cheap pattern-like matching
class Pattern(object):
    def __eq__(self, other):
        return False
    def __repr__(self):
        return 'Pattern()'
class PatternAny(Pattern):
    def __eq__(self, other):
        return True
    __call__ = __eq__
    def __repr__(self):
        return "{:s}({:s})".format('Pattern', '*')
class PatternAnyType(Pattern):
    def __init__(self, other):
        self.type = other
    def __eq__(self, other):
        return isinstance(other, self.type)
    __call__ = __eq__
    def __repr__(self):
        return "{:s}({:s})".format('Pattern', '|'.join(n.__name__ for n in self.type) if hasattr(self.type, '__iter__') else self.type.__name__)

### decorators
class multicase(object):
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
            priority = len(args) - s_args - len(t_args) + (len(args) and (next((float(i) for i,a in enumerate(args[s_args:]) if a in t_args), 0) / len(args))) + sum(0.3 for _ in filter(None, (star, starstar)))

            # check to see if our func is already in the cache
            current = tuple(t_args.get(_,None) for _ in args),(star,starstar)
            for i, (p, (_, t, a)) in enumerate(cache):
                if p != priority: continue
                # verify that it actually matches the entry
                if current == (tuple(t.get(_,None) for _ in a[1]), a[3]):
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

        if len(other) > 1:
            raise SyntaxError("{:s} : More than one callable was specified. Not sure which callable to clone state from. : {!r}".format('.'.join((__name__, cls.__name__)), other))
        return result

    @classmethod
    def document(cls, name, cache):
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
    def prototype(cls, func, types={}):
        args, defaults, (star, starstar) = cls.ex_args(func)
        argsiter = (("{:s}={:s}".format(n, "{:s}".format('|'.join(t.__name__ for t in types[n])) if hasattr(types[n], '__iter__') else types[n].__name__) if types.has_key(n) else n) for n in args)
        res = (argsiter, ("*{:s}".format(star),) if star else (), ("**{:s}".format(starstar),) if starstar else ())
        return "{:s}({:s})".format(func.func_name, ', '.join(itertools.chain(*res)))

    @classmethod
    def match(cls, (args, kwds), heap):
        # FIXME: yep, done in O(n) time.
        for f, types, (sa, af, defaults, (argname, kwdname)) in heap:
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

            # now we can finally start checking that the types match
            if any(not isinstance(v, types[k]) for k, v in zip(af[sa:], a) if k in types):
                continue

            # we should have a match
            return f, (tuple(args[:sa]) + a, wA, wK)

        error_arguments = (n.__class__.__name__ for n in args)
        error_keywords = ("{:s}={:s}".format(n, kwds[n].__class__.__name__) for n in kwds)
        raise LookupError("@multicase.call({:s}, {{{:s}}}) : does not match any defined prototypes : {:s}".format(', '.join(error_arguments) if args else '*()', ', '.join(error_keywords), ', '.join(cls.prototype(f,t) for f,t,_ in heap)))

    @classmethod
    def new_wrapper(cls, func, cache):
        # define the wrapper...
        def callable(*arguments, **keywords):
            heap = [res for _,res in heapq.nsmallest(len(cache), cache)]
            f, (a, w, k) = cls.match((arguments[:],keywords), heap)
            return f(*arguments, **keywords)
            #return f(*(arguments + tuple(w)), **keywords)

        # swap out the original code object with our wrapper's
        f,c = callable, callable.func_code
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
        if isinstance(object, types.FunctionType):
            return object
        elif isinstance(object, types.MethodType):
            return object.im_func
        elif isinstance(object, types.CodeType):
            res, = (n for n in gc.get_referrers(c) if n.func_name == c.co_name and isinstance(n, types.FunctionType))
            return res
        elif isinstance(object, (staticmethod,classmethod)):
            return object.__func__
        raise TypeError, object

    @classmethod
    def reconstructor(cls, n):
        if isinstance(n, types.FunctionType):
            return lambda f: f
        if isinstance(n, types.MethodType):
            return lambda f: types.MethodType(f, n.im_self, n.im_class)
        if isinstance(n, (staticmethod,classmethod)):
            return lambda f: type(n)(f)
        if isinstance(n, types.InstanceType):
            return lambda f: types.InstanceType(type(n), dict(f.__dict__))
        if isinstance(n, (types.TypeType,types.ClassType)):
            return lambda f: type(n)(n.__name__, n.__bases__, dict(f.__dict__))
        raise NotImplementedError, type(func)

    @classmethod
    def ex_args(cls, f):
        c = f.func_code
        varnames_count, varnames_iter = c.co_argcount, iter(c.co_varnames)
        args = tuple(itertools.islice(varnames_iter, varnames_count))
        res = { a : v for v,a in zip(reversed(f.func_defaults or []), reversed(args)) }
        try: starargs = next(varnames_iter) if c.co_flags & cls.CO_VARARGS else ""
        except StopIteration: starargs = ""
        try: kwdargs = next(varnames_iter) if c.co_flags & cls.CO_VARKEYWORDS else ""
        except StopIteration: kwdargs = ""
        return args, res, (starargs, kwdargs)

    @classmethod
    def generatorQ(cls, func):
        func = cls.ex_function(func)
        return bool(func.func_code.co_flags & CO_VARGEN)

class alias(object):
    def __new__(cls, other, klass=None):
        cons,func = multicase.reconstructor(other), multicase.ex_function(other)
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

### asynchronous process monitor
import sys,os,threading,weakref,subprocess,time,itertools,operator

# monitoring an external process' i/o via threads/queues
class process(object):
    """Spawns a program along with a few monitoring threads for allowing asynchronous(heh) interaction with a subprocess.

    mutable properties:
    program -- subprocess.Popen instance
    commandline -- subprocess.Popen commandline
    eventWorking -- threading.Event() instance for signalling task status to monitor threads
    stdout,stderr -- callables that are used to process available work in the taskQueue

    properties:
    id -- subprocess pid
    running -- returns true if process is running and monitor threads are workingj
    working -- returns true if monitor threads are working
    threads -- list of threads that are monitoring subprocess pipes
    taskQueue -- Queue.Queue() instance that contains work to be processed
    exceptionQueue -- Queue.Queue() instance containing exceptions generated during processing
    (process.stdout, process.stderr)<Queue> -- Queues containing output from the spawned process.
    """

    program = None              # subprocess.Popen object
    id = property(fget=lambda s: s.program and s.program.pid or -1)
    running = property(fget=lambda s: False if s.program is None else s.program.poll() is None)
    working = property(fget=lambda s: s.running and not s.eventWorking.is_set())
    threads = property(fget=lambda s: list(s.__threads))
    updater = property(fget=lambda s: s.__updater)

    taskQueue = property(fget=lambda s: s.__taskQueue)
    exceptionQueue = property(fget=lambda s: s.__exceptionQueue)

    def __init__(self, command, **kwds):
        """Creates a new instance that monitors subprocess.Popen(/command/), the created process starts in a paused state.

        Keyword options:
        env<dict> = os.environ -- environment to execute program with
        cwd<str> = os.getcwd() -- directory to execute program  in
        shell<bool> = True -- whether to treat program as an argument to a shell, or a path to an executable
        newlines<bool> = True -- allow python to tamper with i/o to convert newlines
        show<bool> = False -- if within a windowed environment, open up a console for the process.
        paused<bool> = False -- if enabled, then don't start the process until .start() is called
        timeout<float> = -1 -- if positive, then raise a Queue.Empty exception at the specified interval.
        """
        # default properties
        self.__updater = None
        self.__threads = weakref.WeakSet()
        self.__kwds = kwds
        self.commandline = command

        import Queue
        self.eventWorking = threading.Event()
        self.__taskQueue = Queue.Queue()
        self.__exceptionQueue = Queue.Queue()

        self.stdout = kwds.pop('stdout')
        self.stderr = kwds.pop('stderr')

        # start the process
        not kwds.get('paused',False) and self.start(command)

    def start(self, command=None, **options):
        """Start the specified ``command`` with the requested **options"""
        if self.running:
            raise OSError("Process {:d} is still running.".format(self.id))
        if self.updater or len(self.threads):
            raise OSError("Process {:d} management threads are still running.".format(self.id))

        kwds = dict(self.__kwds)
        kwds.update(options)
        command = command or self.commandline

        env = kwds.get('env', os.environ)
        cwd = kwds.get('cwd', os.getcwd())
        newlines = kwds.get('newlines', True)
        shell = kwds.get('shell', False)
        stdout,stderr = options.pop('stdout',self.stdout),options.pop('stderr',self.stderr)
        self.program = process.subprocess(command, cwd, env, newlines, joined=(stderr is None) or stdout == stderr, shell=shell, show=kwds.get('show', False))
        self.commandline = command
        self.eventWorking.clear()

        # monitor program's i/o
        self.__start_monitoring(stdout, stderr)
        self.__start_updater(timeout=kwds.get('timeout',-1))

        # start monitoring
        self.eventWorking.set()
        return self

    def __start_updater(self, daemon=True, timeout=0):
        """Start the updater thread. **used internally**"""
        import Queue
        def task_exec(emit, data):
            if hasattr(emit,'send'):
                res = emit.send(data)
                res and P.write(res)
            else: emit(data)

        def task_get_timeout(P, timeout):
            try:
                emit,data = P.taskQueue.get(block=True, timeout=timeout)
            except Queue.Empty:
                _,_,tb = sys.exc_info()
                P.exceptionQueue.put(StopIteration,StopIteration(),tb)
                return ()
            return emit,data

        def task_get_notimeout(P, timeout):
            return P.taskQueue.get(block=True)

        task_get = task_get_timeout if timeout > 0 else task_get_notimeout

        def update(P, timeout):
            P.eventWorking.wait()
            while P.eventWorking.is_set():
                res = task_get(P, timeout)
                if not res: continue
                emit,data = res

                try:
                    task_exec(emit,data)
                except StopIteration:
                    P.eventWorking.clear()
                except:
                    P.exceptionQueue.put(sys.exc_info())
                finally:
                    P.taskQueue.task_done()
                continue
            return

        self.__updater = updater = threading.Thread(target=update, name="thread-%x.update"% self.id, args=(self,timeout))
        updater.daemon = daemon
        updater.start()
        return updater

    def __start_monitoring(self, stdout, stderr=None):
        """Start monitoring threads. **used internally**"""
        program = self.program
        name = "thread-{:x}".format(program.pid)

        # create monitoring threads + coroutines
        if stderr:
            res = process.monitorPipe(self.taskQueue, (stdout,program.stdout),(stderr,program.stderr), name=name)
        else:
            res = process.monitorPipe(self.taskQueue, (stdout,program.stdout), name=name)

        res = map(None, res)
        # attach a method for injecting data into a monitor
        for t,q in res: t.send = q.send
        threads,senders = zip(*res)

        # update threads for destruction later
        self.__threads.update(threads)

        # set things off
        for t in threads: t.start()

    @staticmethod
    def subprocess(program, cwd, environment, newlines, joined, shell=True, show=False):
        """Create a subprocess using subprocess.Popen."""
        stderr = subprocess.STDOUT if joined else subprocess.PIPE
        if os.name == 'nt':
            si = subprocess.STARTUPINFO()
            si.dwFlags = subprocess.STARTF_USESHOWWINDOW
            si.wShowWindow = 0 if show else subprocess.SW_HIDE
            cf = subprocess.CREATE_NEW_CONSOLE if show else 0
            return subprocess.Popen(program, universal_newlines=newlines, shell=shell, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=stderr, close_fds=False, startupinfo=si, creationflags=cf, cwd=cwd, env=environment)
        return subprocess.Popen(program, universal_newlines=newlines, shell=shell, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=stderr, close_fds=True, cwd=cwd, env=environment)

    @staticmethod
    def monitorPipe(q, (id,pipe), *more, **options):
        """Attach a coroutine to a monitoring thread for stuffing queue `q` with data read from `pipe`

        Yields a list of (thread,coro) tuples given the arguments provided.
        Each thread will read from `pipe`, and stuff the value combined with `id` into `q`.
        """
        def stuff(q,*key):
            while True: q.put(key+((yield),))

        for id,pipe in itertools.chain([(id,pipe)],more):
            res,name = stuff(q,id), "{:s}<{!r}>".format(options.get('name',''),id)
            yield process.monitor(res.next() or res.send, pipe, name=name),res
        return

    @staticmethod
    def monitor(send, pipe, blocksize=1, daemon=True, name=None):
        """Spawn a thread that reads `blocksize` bytes from `pipe` and dispatches it to `send`

        For every single byte, `send` is called. The thread is named according to
        the `name` parameter.

        Returns the monitoring threading.thread instance
        """
        def shuffle(send, pipe):
            while not pipe.closed:
                data = pipe.read(blocksize)
                if len(data) == 0:
                    # pipe.read syscall was interrupted. so since we can't really
                    # determine why (cause...y'know..python), stop dancing so
                    # the parent will actually be able to terminate us
                    break
                map(send,data)
            return
        if name:
            monitorThread = threading.Thread(target=shuffle, name=name, args=(send,pipe))
        else:
            monitorThread = threading.Thread(target=shuffle, args=(send,pipe))
        monitorThread.daemon = daemon
        return monitorThread

    def __format_process_state(self):
        if self.program is None:
            return "Process \"{:s}\" {:s}.".format(self.commandline, 'was never started')
        res = self.program.poll()
        return "Process {:d} {:s}".format(self.id, 'is still running' if res is None else "has terminated with code {:d}".format(res))

    def write(self, data):
        """Write `data` directly to program's stdin"""
        if self.running and not self.program.stdin.closed:
            if self.updater and self.updater.is_alive():
                return self.program.stdin.write(data)
            raise IOError("Unable to write to stdin for process {:d}. Updater thread has prematurely terminated.".format(self.id))
        raise IOError("Unable to write to stdin for process. {:s}.".format(self.__format_process_state()))

    def close(self):
        """Closes stdin of the program"""
        if self.running and not self.program.stdin.closed:
            return self.program.stdin.close()
        raise IOError("Unable to close stdin for process. {:s}.".format(self.__format_process_state()))

    def signal(self, signal):
        """Raise a signal to the program"""
        if self.running:
            return self.program.send_signal(signal)
        raise IOError("Unable to raise signal {!r} to process. {:s}.".format(signal, self.__format_process_state()))

    def exception(self):
        """Grab an exception if there's any in the queue"""
        if self.exceptionQueue.empty(): return
        res = self.exceptionQueue.get()
        self.exceptionQueue.task_done()
        return res

    def wait(self, timeout=0.0):
        """Wait a given amount of time for the process to terminate"""
        program = self.program
        if program is None:
            raise RuntimeError("Program {:s} is not running.".format(self.commandline))

        if not self.running: return program.returncode
        self.updater.is_alive() and self.eventWorking.wait()

        if timeout:
            t = time.time()
            while self.running and self.eventWorking.is_set() and time.time() - t < timeout:        # spin cpu until we timeout
                if not self.exceptionQueue.empty():
                    res = self.exception()
                    raise res[0],res[1],res[2]
                continue
            return program.returncode if self.eventWorking.is_set() else self.__terminate()

        # return program.wait() # XXX: doesn't work correctly with PIPEs due to
        #   pythonic programmers' inability to understand os semantics

        while self.running and self.eventWorking.is_set():
            if not self.exceptionQueue.empty():
                res = self.exception()
                raise res[0],res[1],res[2]
            continue    # ugh...poll-forever/kill-cpu until program terminates...

        if not self.eventWorking.is_set():
            return self.__terminate()
        return program.returncode

    def stop(self):
        self.eventWorking.clear()
        return self.__terminate()

    def __terminate(self):
        """Sends a SIGKILL signal and then waits for program to complete"""
        self.program.kill()
        while self.running: continue

        self.__stop_monitoring()
        if self.exceptionQueue.empty():
            return self.program.returncode

        res = self.exception()
        raise res[0],res[1],res[2]

    def __stop_monitoring(self):
        """Cleanup monitoring threads"""
        P = self.program
        if P.poll() is None:
            raise RuntimeError("Unable to stop monitoring while process {!r} is still running.".format(P))

        # stop the update thread
        self.eventWorking.clear()

        # forcefully close pipes that still open, this should terminate the monitor threads
        #   also, this fixes a resource leak since python doesn't do this on subprocess death
        for p in (P.stdin,P.stdout,P.stderr):
            while p and not p.closed:
                try: p.close()
                except: pass
            continue

        # join all monitoring threads
        map(operator.methodcaller('join'), self.threads)

        # now spin until none of them are alive
        while len(self.threads) > 0:
            for th in self.threads[:]:
                if not th.is_alive(): self.__threads.discard(th)
                del(th)
            continue

        # join the updater thread, and then remove it
        self.taskQueue.put(None)
        self.updater.join()
        assert not self.updater.is_alive()
        self.__updater = None
        return

    def __repr__(self):
        ok = self.exceptionQueue.empty()
        state = "running pid:{:d}".format(self.id) if self.running else "stopped cmd:\"{:s}\"".format(self.commandline)
        threads = [
            ('updater', 0 if self.updater is None else self.updater.is_alive()),
            ('input/output', len(self.threads))
        ]
        return "<process {:s}{:s} threads{{{:s}}}>".format(state, (' !exception!' if not ok else ''), ' '.join("{:s}:{:d}".format(n,v) for n,v in threads))

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
    if hasattr(stdout,'send'):
        res = stdout.next()
        res and P.write(res)
    if hasattr(stderr,'send'):
        res = stderr.next()
        res and P.write(res)

    # spawn the sub-process
    return process(command, stdout=stdout, stderr=stderr, **options)

### scheduler
class execution(object):
    __slots__ = ('queue','state','result','ev_unpaused','ev_terminating')
    __slots__+= ('thread','lock')

    def __init__(self):
        '''Execute a function asynchronously in another thread.'''

        # management of execution queue
        res = multiprocessing.Lock()
        self.queue = multiprocessing.Condition(res)
        self.state = []

        # results
        self.result = Queue.Queue()

        # thread management
        self.ev_unpaused = multiprocessing.Event()
        self.ev_terminating = multiprocessing.Event()
        self.thread = threading.Thread(target=self.__run__, name="Thread-{:s}-{:x}".format(self.__class__.__name__, id(self)))

        # FIXME: we can support multiple threads, but since this is
        #        being bound by a single lock due to my distrust for IDA
        #        and race-conditions...we only use one.
        self.lock = multiprocessing.Lock()

        return self.__start()

    def release(self):
        '''Release any resources required to execute a function asynchronously.'''
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
        return "<class '{:s}'> {:s} Queue:{:d} Results:{:d}".format('.'.join(('internal',__name__,cls.__name__)), state, len(res), self.result.unfinished_tasks)

    running = property(fget=lambda s: s.thread.is_alive() and s.ev_unpaused.is_set() and not s.ev_terminating.is_set())
    dead = property(fget=lambda s: s.thread.is_alive())

    def notify(self):
        '''Notify the execution queue that it should process anything that is queued.'''
        logging.debug("{:s}.notify : Waking up execution queue. : {!r}".format('.'.join(('internal',__name__,cls.__name__)), self))
        self.queue.acquire()
        self.queue.notify()
        self.queue.release()

    def next(self):
        '''Notify the execution queue that a result is needed, then return the next one available.'''
        self.queue.acquire()
        while self.state:
            self.queue.notify()
        self.queue.release()

        if self.result.empty():
            raise StopIteration
        return self.pop()

    def __start(self):
        cls = self.__class__
        logging.debug("{:s}.start : Starting execution queue thread. : {!r}".format('.'.join(('internal',__name__,cls.__name__)), self.thread))
        self.ev_terminating.clear(), self.ev_unpaused.clear()
        self.thread.daemon = True
        return self.thread.start()

    def __stop(self):
        cls = self.__class__
        logging.debug("{:s}.stop : Terminating execution queue thread. : {!r}".format('.'.join(('internal',__name__,cls.__name__)), self.thread))
        if not self.thread.is_alive():
            cls = self.__class__
            logging.warn("{:s}.stop : Execution queue has already been terminated. : {!r}".format('.'.join(('internal',__name__,cls.__name__)), self))
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
            logging.fatal("{:s}.start : Unable to resume an already terminated execution queue. : {!r}".format('.'.join(('internal',__name__,cls.__name__)), self))
            return False
        logging.info("{:s}.start : Resuming execution queue. :{!r}".format('.'.join(('internal',__name__,cls.__name__)), self.thread))
        res, _ = self.ev_unpaused.is_set(), self.ev_unpaused.set()
        self.queue.acquire()
        self.queue.notify_all()
        self.queue.release()
        return not res

    def stop(self):
        '''Pause the execution queue.'''
        cls = self.__class__
        if not self.thread.is_alive():
            logging.fatal("{:s}.stop : Unable to pause an already terminated execution queue. : {!r}".format('.'.join(('internal',__name__,cls.__name__)), self))
            return False
        logging.info("{:s}.stop : Pausing execution queue. : {!r}".format('.'.join(('internal',__name__,cls.__name__)), self.thread))
        res, _ = self.ev_unpaused.is_set(), self.ev_unpaused.clear()
        self.queue.acquire()
        self.queue.notify_all()
        self.queue.release()
        return res

    def push(self, callable, *args, **kwds):
        '''Push ``callable`` with the provided ``args`` and ``kwds`` onto the execution queue.'''
        # package it all into a single function
        res = functools.partial(callable, *args, **kwds)

        cls = self.__class__
        logging.debug("{:s}.push : Adding callable {!r} to execution queue. : {!r}".format('.'.join(('internal',__name__,cls.__name__)), callable, self))
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
            logging.fatal("{:s}.pop : Refusing to wait for a result when execution queue has already terminated. : {!r}".format('.'.join(('internal',__name__,cls.__name__)), self))
            raise Queue.Empty

        logging.debug("{:s}.pop : Popping result off of execution queue. : {!r}".format('.'.join(('internal',__name__,cls.__name__)), self))
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
            callable = (yield res, error)
            lock.acquire()
            try:
                res = callable()
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

        logging.debug("{:s}.running : Execution queue is now running. : {!r}".format('.'.join(('internal',__name__,cls.__name__)), self.thread))
        while not self.ev_terminating.is_set():
            # check if we're allowed to execute
            if not self.ev_unpaused.is_set():
                self.ev_unpaused.wait()

            # pull a callable out of the queue
            logging.debug("{:s}.running : Waiting for an item.. : {!r}".format('.'.join(('internal',__name__,cls.__name__)), self.thread))
            self.queue.acquire()
            item = next(consumer)
            self.queue.release()

            if not self.ev_unpaused.is_set():
                self.ev_unpaused.wait()

            # check if we're terminating
            if self.ev_terminating.is_set(): break

            # now we can execute it
            logging.debug("{:s}.running : Executing {!r} asynchronously. : {!r}".format('.'.join(('internal',__name__,cls.__name__)), item, self.thread))
            res, err = executor.send(item)

            # and stash our result
            logging.debug("{:s}.running : Received result {!r} from {!r}. : {!r}".format('.'.join(('internal',__name__,cls.__name__)), (res,err), item, self.thread))
            self.result.put((item,res,err))
        return

# FIXME: figure out how to match against a bounds
class matcher(object):
    def __init__(self):
        self.__predicate__ = {}
    def __attrib__(self, *attribute):
        if not attribute:
            return lambda n: n
        res = [(operator.attrgetter(a) if isinstance(a,basestring) else a) for a in attribute]
        return lambda o: tuple(x(o) for x in res) if len(res) > 1 else res[0](o)
    def attribute(self, type, *attribute):
        attr = self.__attrib__(*attribute)
        self.__predicate__[type] = lambda v: compose(attr, functools.partial(functools.partial(operator.eq, v)))
    def mapping(self, type, function, *attribute):
        attr = self.__attrib__(*attribute)
        mapper = compose(attr, function)
        self.__predicate__[type] = lambda v: compose(mapper, functools.partial(operator.eq, v))
    def boolean(self, type, function, *attribute):
        attr = self.__attrib__(*attribute)
        self.__predicate__[type] = lambda v: compose(attr, functools.partial(function, v))
    def predicate(self, type, *attribute):
        attr = self.__attrib__(*attribute)
        self.__predicate__[type] = functools.partial(compose, attr)
    def match(self, type, value, iterable):
        matcher = self.__predicate__[type](value)
        return itertools.ifilter(matcher, iterable)

if __name__ == '__main__':
    fn = lambda: 0
    del(fn)

    @multicase()
    def fn():
        '''contains no arguments'''
        return 0

    @multicase(name=basestring)
    def fn(name):
        '''contains `name` which is a string'''
        return 1

    @multicase()
    def fn(something):
        '''contains an unknown field `something`'''
        return 2

    @multicase(blah1=six.integer_types)
    def fn(blah1, blah2):
        """This has the following format:
        blah1 -- is an int
        blah2 -- is unknown"""
        return 3

    @multicase(blah=str, blah2=int)
    def fn(blah,blah2,*args):
        return 4

    @multicase(blah=str, blah2=int)
    def fn(blah,blah2,**kwds):
        return 5

    print fn()
