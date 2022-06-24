import sys, os, logging
import six, imp, fnmatch, ctypes, types
import idaapi

# Point this at the repository directory
root = idaapi.get_user_idadir()

# The following classes contain the pretty much all of the loader logic used by the
# plugin. This is being defined here so that this file can also be used as a module.
class internal_api(object):
    """
    Loader base-class for any api that's based on files contained within a directory.
    """
    os, imp, fnmatch = os, imp, fnmatch
    def __init__(self, directory, **attributes):
        '''Initialize the api using the contents within the specified `directory`.'''
        self.path = self.os.path.realpath(directory)
        [ setattr(self, name, attribute) for name, attribute in attributes.items() ]

    ### Api operations
    def load_api(self, path):
        '''Load the specified `path` into a module that can be used.'''
        path, filename = self.os.path.split(path)
        name, _ = self.os.path.splitext(filename)
        return self.imp.find_module(name, [path])

    def iterate_api(self, include='*.py', exclude=None):
        """Iterate through all of the files in the directory specified when initializing the loader.

        The `include` string is a glob that specifies which files are part of the loader's api.
        If the `exclude` glob is specified, then exclude files that match it from the loader api.
        """
        result = []
        for filename in self.fnmatch.filter(self.os.listdir(self.path), include):
            if exclude and self.fnmatch.fnmatch(filename, exclude):
                continue

            path = self.os.path.join(self.path, filename)
            _, ext = self.os.path.splitext(filename)

            left, right = (None, None) if include == '*' else (include.index('*'), len(include) - include.rindex('*'))
            modulename = filename[left : -right + 1]
            yield modulename, path
        return

    def new_api(self, modulename, path):
        '''Load the file found at `path` into the specified `modulename`.'''
        file, path, description = self.load_api(path)
        try:
            return self.imp.load_module(modulename, file, path, description)
        finally: file.close()

    ### Module operations
    def new_module(self, fullname, documentation=None):
        '''Create a new module (empty) with the specified `fullname` and the provided `documentation`.'''
        res = self.imp.new_module(fullname)
        res.__package__ = fullname
        res.__doc__ = documentation or ''
        return res

    def find_module(self, fullname, path=None):
        raise NotImplementedError

    def load_module(self, fullname):
        raise NotImplementedError

class internal_path(internal_api):
    """
    Loader class which provides all api composed of all of the files within a directory
    as modules that can always be imported from anywhere.
    """
    def __init__(self, path, **attrs):
        '''Initialize the loader using the files from the directory specified by `path`.'''
        super(internal_path, self).__init__(path)
        attrs.setdefault('include', '*.py')
        self.attrs, self.cache = attrs, { name : path for name, path in self.iterate_api(**attrs) }

    def find_module(self, fullname, path=None):
        '''If the module with the name `fullname` matches one of the files handled by our api, then act as their loader.'''
        return self if path is None and fullname in self.cache else None

    def load_module(self, fullname):
        '''Iterate through all of the modules that we can handle, and then load it if we've been asked.'''
        self.cache = { name : path for name, path in self.iterate_api(**self.attrs) }
        if fullname not in self.cache:
            raise ImportError("path-loader ({:s}) was not able to find a module named `{:s}`".format(self.path, fullname))
        return self.new_api(fullname, self.cache[fullname])

class internal_submodule(internal_api):
    """
    Loader class which provides an api composed of all of the files within a
    directory, and binds them to a module which is used to access them.
    """
    sys = sys
    def __init__(self, __name__, path, **attrs):
        '''Initialize the loader using `__name__` as the name of the submodule using the files underneath the directory `path`.'''
        super(internal_submodule, self).__init__(path)
        attrs.setdefault('include', '*.py')
        self.__name__, self.attrs = __name__, attrs

    def find_module(self, fullname, path=None):
        '''If the module with the name `fullname` matches our submodule name, then act as its loader.'''
        return self if path is None and fullname == self.__name__ else None

    def new_api(self, modulename, path):
        '''Load the file found at the specified `path` as a submodule with the specified `modulename`.'''
        cls, fullname = self.__class__, '.'.join([self.__name__, modulename])
        res = super(cls, self).new_api(fullname, path)
        res.__package__ = self.__name__
        return res

    def load_module(self, fullname):
        '''Iterate through all of the modules that we can handle, load the submodule with them, and return it.'''
        module = self.sys.modules[fullname] = self.new_module(fullname)
        # FIXME: make module a lazy-loaded object for fetching module-code on-demand

        # Build a temporary cache for the module names and paths to load the api,
        # and use them to build their documentation.
        cache = { name : path for name, path in self.iterate_api(**self.attrs) }
        module.__doc__ = '\n'.join("{:s} -- {:s}".format(name, path) for name, path in sorted(cache.items()))

        # Load each submodule that composes the api, and attach it to the returned submodule.
        stack, count, result = [item for item in cache.items()], len(cache), {}
        while stack and count > 0:
            name, path = stack.pop(0)

            # Take the submodule name we popped off of the cache, and try and load it.
            # If we were able to load it successfully, then we just need to attach the
            # loaded code as a submodule of the object we're going to return.
            try:
                res = self.new_api(name, path)
                modulename = '.'.join([res.__package__, name])

            # If an exception was raised, then remember it so that we can let the user
            # know after we've completely loaded the module.
            except Exception as E:
                import logging
                logging.info("{:s} : Error trying to import module `{:s}` from {!s}. Queuing it until later.".format(self.__name__, name, path), exc_info=True)

                # If we caught an exception while trying to import the module, then stash
                # our exception info state into a dictionary and decrease a counter. This
                # is strictly to deal with module recursion issues in Python3.
                result[name], count = sys.exc_info(), count - 1
                stack.append((name, path))

            # Add the submodule that we loaded into the module that we're going to return.
            else:
                setattr(module, name, res)
            continue

        # If we weren't able to load one of the submodules that should've been in our cache,
        # then go through all of our backtraces and log the exception that was raised.
        if stack:
            import logging, traceback
            for name, path in stack:
                logging.fatal("{:s} : Error trying to import module `{:s}` from {!s}.".format(self.__name__, name, path), exc_info=result[name])
            return module

        # If we caught an exception despite our stack being empty, then this is because of a
        # recursion issue. In case someone wants to track these situations down, we go through
        # our caught exceptions and create some logging events with the backtrace. These errors
        # are non-fatal because importing another sub-module helped resolve it.
        import logging
        for name, exc_info in result.items():
            logging.info("{!s} : Encountered a non-fatal exception while trying to import recursive module `{:s}` from {!s}".format(self.__name__, name, cache[name]), exc_info=result[name])

        # Return the module that we just created.
        return module

class internal_object(object):
    """
    Loader class which will simply expose an object instance as the module.
    """
    sys = sys
    def __init__(self, __name__, object):
        '''Initialize the loader with the specified `__name__` and returning the provided `object` as its module.'''
        self.__name__, self.object = __name__, object

    def find_module(self, fullname, path=None):
        '''If the module being searched for matches our `fullname`, then act as its loader.'''
        return self if path is None and fullname == self.__name__ else None

    def load_module(self, fullname):
        '''Return the specific object for the module specified by `fullname`.'''
        if fullname != self.__name__:
            raise ImportError("object-loader ({:s}) was not able to find a module named `{:s}`".format(self.__name__, fullname))
        module = self.sys.modules[fullname] = self.object
        return module

class plugin_module(object):
    """
    Loader class which iterates through all of the files in a directory, and
    manually initializes each plugin similar to the way `idaapi.plugin_t` is
    supposed to be initialized.
    """
    def __init__(self, path, **attrs):
        # FIXME: go through all files in plugin/ and call PLUGIN_ENTRY() on each module
        #        this should return an idaapi.plugin_t.

        # idaapi.plugin_t will contain an init, run, and term method.
        # also, are some attributes to process:
        # 'wanted_name' which is for idc.
        # 'wanted_hotkey', which should be mapped to a keypress.
        # 'comment' self-explanatory
        # 'help' self-explanatory

        # hotkey can be done by:
        # idaapi.CompileLine('static myname() { RunPythonStateMent("CallSomePython()") }')
        # idc.AddHotKey(module.wanted_hotkey, "myname")

        # idaapi.require
        pass

# The following logic is responsible for replacing a namespace with
# the contents namespace that represents the entirety of the plugin.
def load(namespace, preserve=()):
    module = imp.load_source('__root__', os.path.join(root, '__root__.py'))

    # save certain things within the namespace
    preserved = {symbol : value for symbol, value in namespace.items() if symbol in preserve}

    # empty out the entire namespace so that we can replace it
    [namespace.pop(symbol) for symbol in namespace.copy() if not symbol.startswith('__')]

    # re-populate with the root namespace while restoring any symbols
    # that needed to be preserved.
    namespace.update({symbol : value for symbol, value in module.__dict__.items() if not symbol.startswith('__')})
    namespace.update({symbol : value for symbol, value in preserved.items()})

# Just a ctypes wrapper so that we can access the internal IDA api.
library = ctypes.WinDLL if os.name == 'nt' else ctypes.CDLL

# The following code is responsible for seeding Python's loader by
# yielding each of the objects that need to be added to its meta_path.
def finders():
    '''Yield each finder that will be used by the plugin to locate its modules.'''

    # IDA's native lower-level api
    if sys.platform in {'darwin'}:
        yield internal_object('ida', library(idaapi.idadir("libida{:s}.dylib".format('' if idaapi.BADADDR < 0x100000000 else '64'))))

    elif sys.platform in {'linux', 'linux2'}:
        yield internal_object('ida', library(idaapi.idadir("libida{:s}.so".format('' if idaapi.BADADDR < 0x100000000 else '64'))))

    elif sys.platform in {'win32'}:
        if os.path.exists(idaapi.idadir('ida.wll')):
            yield internal_object('ida', library(idaapi.idadir('ida.wll')))
        else:
            yield internal_object('ida', library(idaapi.idadir("ida{:s}.dll".format('' if idaapi.BADADDR < 0x100000000 else '64'))))

    else:
        logging.warning("{:s} : Unable to load IDA's native api via ctypes. Ignoring...".format(__name__))

    # private (internal) api
    yield internal_submodule('internal', os.path.join(root, 'base'), include='_*.py')

    # public api
    yield internal_path(os.path.join(root, 'base'), exclude='_*.py')
    yield internal_path(os.path.join(root, 'misc'))

    # custom and application api
    for subdir in ['custom', 'app']:
        yield internal_submodule(subdir, os.path.join(root, subdir))
    return

# The following logic is simply for detecting the version of IDA and
# for stashing it directly into the "idaapi" module.

# needed because IDA 6.95 is fucking stupid and sets the result of idaapi.get_kernel_version() to a string
def host_version():
    '''Return the version of the host application as the major, minor, and a floating-point variation.'''

    # if the api doesn't exist, then go back to some crazy version.
    if not hasattr(idaapi, 'get_kernel_version'):
        return 6, 0, 6.0

    import math
    res = str(idaapi.get_kernel_version())      # force it to a str because IDA 7.0 "fixed" it
    major, minor = map(int, res.split('.', 2))
    minor = int("{:<02d}".format(minor))
    if minor > 0:
        count = 1 + math.floor(math.log10(minor))
        return major, minor, float(major) + minor * pow(10, -count)
    return major, minor, float(major)

def patch_version(module):
    '''Patch the version of the host application into a given module.'''
    version = host_version()
    module.__version_major__, module.__version_minor__, module.__version__ = version
    return version

# The following logic is the display hook that we install in order to
# control how all of our output renders in the REPL.
class DisplayHook(object):
    """
    Re-implementation of IDAPython's displayhook that doesn't tamper with
    classes that inherit from base classes
    """
    def __init__(self, output, displayhook):
        self.orig_displayhook = displayhook or sys.displayhook

        # Save our output callable so we can use it to write raw
        # and unprocessed information to it.
        self.output = output

    def format_seq(self, num_printer, storage, item, open, close):
        storage.append(open)
        for idx, el in enumerate(item):
            if idx > 0:
                storage.append(', ')
            self.format_item(num_printer, storage, el)
        storage.append(close)

    def format_basestring(self, string):
        # FIXME: rather than automatically evaluating the string as we're
        #        currently doing, it'd be much cleaner if we just format the
        #        result from a function with some sort of wrapper object. This
        #        way we can check its type, and then choose whether to unwrap it
        #        or not. This can be done with a decorator of some sort that
        #        communicates to this implementation that it will need to
        #        distinguish between printable strings that we can output and
        #        strings that should be processed by the user.
        # XXX: maybe we can even use this wrapper object to allow this class to
        #      handle aligning columns in a table automatically such as when
        #      more than one element in a row is being returned.
        try:
            result = u"{!r}".format(string)
        except UnicodeDecodeError:
            import codecs
            encoded, _ = codecs.escape_encode(string)
            result = u"'{!s}'".format(encoded)
        return result

    def format_ctypes(self, num_printer, storage, item):
        cls, size = item.__class__, ctypes.sizeof(item)
        if isinstance(item, ctypes._SimpleCData):
            storage.append("{:s}({:#0{:d}x})".format(cls.__name__, item.value, 2 + 2 * size))

        # if it's anything else (or an unknown), then use the default formatter.
        else:
            storage.append("{!r}".format(item))
        return

    def format_item(self, num_printer, storage, item):
        if item is None or isinstance(item, bool):
            storage.append("{!s}".format(item))
        elif isinstance(item, six.string_types):
            storage.append(self.format_basestring(item))
        elif isinstance(item, six.integer_types):
            storage.append(num_printer(item))
        elif isinstance(item, idaapi.tinfo_t):
            storage.append("{!s}".format(item.dstr()))
        elif isinstance(item, (ctypes._SimpleCData, ctypes._Pointer, ctypes._CFuncPtr, ctypes.Array, ctypes.Structure)):
            self.format_ctypes(num_printer, storage, item)
        elif item.__class__ is list:
            self.format_seq(num_printer, storage, item, '[', ']')
        elif item.__class__ is tuple:
            self.format_seq(num_printer, storage, item, '(', ')')
        elif item.__class__ is set:
            self.format_seq(num_printer, storage, item, 'set([', '])')
        elif item.__class__ is dict:
            storage.append('{')
            for idx, pair in enumerate(item.items()):
                if idx > 0:
                    storage.append(', ')
                self.format_item(num_printer, storage, pair[0])
                storage.append(": ")
                self.format_item(num_printer, storage, pair[1])
            storage.append('}')
        else:
            storage.append("{!r}".format(item))

    def _print_hex(self, x):
        return "{:#x}".format(x)

    def displayhook(self, item):
        if item is None or not hasattr(item, '__class__') or item.__class__ is bool:
            self.orig_displayhook(item)
            return
        try:
            storage = []
            if idaapi.__version__ < 7.0:
                import idaapi as ida_idp
            else:
                import ida_idp
            num_printer = self._print_hex
            dn = ida_idp.ph_get_flag() & ida_idp.PR_DEFNUM
            if dn == ida_idp.PRN_OCT:
                num_printer = oct
            elif dn == ida_idp.PRN_DEC:
                num_printer = str
            elif dn == ida_idp.PRN_BIN:
                num_printer = bin
            self.format_item(num_printer, storage, item)
            self.output("%s\n" % "".join(storage))
        except Exception:
            import traceback
            traceback.print_exc()
            self.orig_displayhook(item)
