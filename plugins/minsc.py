"""
IDA-Minsc plugin -- https://arizvisa.github.io/ida-minsc

This file contains the entirety of the logic that is used to load the
plugin. The plugin is (mostly) a library that aims to simplify IDAPython.
However, it utilizes hooks and keyboard shortcuts in a variety of ways in
order to keep track of the changes that the user may make within their
database. Essentially the goal of this plugin is to make absolutely
_everything_ that's useful in the database serializeable and queryable
so that it can be exchanged with things outside of the database.

If you wish to change the directory that the plugin is loaded from, specify the
location of the plugin's git repository in the variable that is marked below.
"""

import sys, os, logging
import six, imp, fnmatch, ctypes, types
import idaapi

# :: Point this variable at the directory containing the repository of the plugin ::
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

# The following logic is actually responsible for starting up the whole
# plugin. This is done with by trying with a notification, falling back
# to a timer, and then straight-up executing things if all else fails.
def startup():
    '''Patch in a notification hander and start up everything left in the plugin.'''

    # First check that we've installed the version patch and it's the
    # right type as everything literally revolves around that critical step.
    if not hasattr(idaapi, '__version__'):
        raise SystemError("{:s} : Unable to start up plugin due to the \"{:s}\" attribute not having been assigned.".format(__name__, '.'.join([idaapi.__module__, '__version_'])))

    if not isinstance(idaapi.__version__, float):
        raise SystemError("{:s} : Unable to start up plugin due to the \"{:s}\" attribute not being a valid type ({!r})".format(__name__, '.'.join([idaapi.__module__, '__version_']), idaapi.__version__))

    # Now we need to make sure we have access to our internal module.
    # We can simply trap for ImportError to ensure this works.
    try:
        import internal
        internal.interface

    except ImportError:
        logging.critical("{:s} : An error occured while trying to access the \"{:s}\" module.".format(__name__, 'internal'), exc_info=True)
        raise SystemError("{:s} : Unable to start up plugin without being able to access its \"{:s}\" modules.".format(__name__, 'internal'))

    except AttributeError:
        logging.critical("{:s} : An error occured while trying to access the \"{:s}\" module.".format(__name__, '.'.join(['internal', 'interface'])), exc_info=True)
        raise SystemError("{:s} : Unable to start up plugin due to an error while loading its \"{:s}\" modules.".format(__name__, 'internal'))

    # The next module we need to make sure we have access to is our
    # hooks module which contains all of our startup logic.
    try:
        import hooks

    except ImportError:
        logging.critical("{:s} : An error occured while trying to access the \"{:s}\" module.".format(__name__, 'hooks'), exc_info=True)
        raise SystemError("{:s} : Unable to start up plugin without being able to access its \"{:s}\" module.".format(__name__, 'hooks'))

    # Finally we can construct our priority notification class and
    # inject it into IDA. This needs to exist in order for everything
    # to initialize and deinitialize properly.
    idaapi.__notification__ = notification = internal.interface.prioritynotification()

    # Now we can install our hooks that initialize/uninitialize MINSC
    try:
        notification.add(idaapi.NW_INITIDA, hooks.make_ida_not_suck_cocks, -1000)

    # If installing that hook failed, then check if we're running in batch mode. If
    # we are, then just immediately register things.
    except Exception:
        TIMEOUT = 5
        if idaapi.cvar.batch:
            hooks.ida_is_busy_sucking_cocks()

        # Otherwise warn the user about this and register our hook with a timer.
        else:
            logging.warning("Unable to add notification for idaapi.NW_INITIDA ({:d}). Registering a {:.1f} second timer to setup hooks...".format(idaapi.NW_INITIDA, TIMEOUT))
            idaapi.register_timer(TIMEOUT, hooks.ida_is_busy_sucking_cocks)
        del(TIMEOUT)

    # If we were able to hook NW_INITIDA, then the NW_TERMIDA hook should also work.
    else:
        try:
            notification.add(idaapi.NW_TERMIDA, hooks.make_ida_suck_cocks, +1000)

        # Installing the termination hook failed, but it's not really too important...
        except Exception:
            logging.warning("Unable to add notification for idaapi.NW_TERMIDA ({:d}).".format(idaapi.NW_TERMIDA))
    return

# Now we can define our plugin_t that literally does nothing if we've already been
# loaded via the idapythonrc.py file and control the entire default namespace.

class MINSC(idaapi.plugin_t):
    wanted_name = 'About Minsc'
    comment = 'Makes IDAPython Not Suck Completely.'
    wanted_hotkey = ''

    flags = idaapi.PLUGIN_FIX
    state = None

    help = 'You should totally check out the `dill` Python module so you can save your game.'

    def get_loader(self):
        '''Return the loader containing all the components needed for loading and initializing the plugin'''
        import imp

        # We explicitly create our own version of the loader from the current
        # file. The functionality we need is actually within our current module,
        # but IDA was responsible for loading it. Most importantly, though, is
        # that the loader is intended to be completely thrown away after usage.
        try:
            filename = __file__ if os.path.exists(__file__) else os.path.join(root, 'plugins', 'minsc.py')
            module = imp.load_source("{:s}-loader".format(self.wanted_name), filename)

        except IOError:
            logging.critical("{:s} : A critical error occurred while trying to read the plugin loader from the file: {:s}".format(self.wanted_name, filename), exc_info=True)

        except ImportError:
            logging.critical("{:s} : A critical error occurred while initializing the plugin loader in \"{:s}\"".format(self.wanted_name, filename), exc_info=True)

        except Exception:
            logging.critical("{:s} : A critical error occurred while initializing the plugin loader".format(self.wanted_name, filename), exc_info=True)

        return module

    def init(self):
        version = getattr(idaapi, '__version__', None)

        # Check our version.. but not really. We're only checking it to see
        # whether the plugin has been loaded yet. If our version if a float,
        # then our module finders have already been loaded and we just need
        # to persist ourselves.
        if isinstance(version, float):
            self.state = 'persistent'
            return idaapi.PLUGIN_KEEP

        # Now the version hasn't been assigned yet, then the user didn't
        # install this globally. This means that we don't control the primary
        # namespace. So we'll need to load ourselves still and then afterwards
        # we can uninstall ourselves whenever our plugin is asked to terminate.
        loader = self.get_loader()
        if not loader:
            raise SystemError("{:s} : Unable to get the loader required by the plugin.".format(self.wanted_name))

        # Seed the metapath, then patch the version into the idaapi module.
        sys.meta_path.extend(loader.finders())
        _, _, version = loader.patch_version(idaapi)

        # Check if IDAPython (6.95) has replaced the display hook with their
        # own version. We're going to undo exactly what they did, because
        # we're going to replace it with our own anyways.
        ida_idaapi = __import__('ida_idaapi') if version >= 6.95 else idaapi
        if hasattr(ida_idaapi, '_IDAPython_displayhook') and hasattr(ida_idaapi._IDAPython_displayhook, 'orig_displayhook'):
            orig_displayhook = ida_idaapi._IDAPython_displayhook.orig_displayhook
            del(ida_idaapi._IDAPython_displayhook.orig_displayhook)

            sys.displayhook = loader.DisplayHook(sys.stdout.write, orig_displayhook).displayhook

        # If it's the builtin displayhook then we can use it as-is.
        elif getattr(sys.displayhook, '__module__', '') == 'sys':
            sys.displayhook = loader.DisplayHook(sys.stdout.write, sys.displayhook).displayhook

        # Anything else means that some plugin or somebody else did something
        # crazy, and we have no idea how to recover from this.
        else:
            logging.warning("{:s} : Skipping installation of the display hook at \"{:s}\" due to a lack of awareness about the current one ({!r}).".format(self.wanted_name, '.'.join(['sys', 'displayhook']), sys.displayhook))

        # Now we'll try and tamper with the user's namespace. We'll search through
        # Python's module list, and if we find it we'll just swap it out for root.
        if '__main__' in sys.modules:
            ns = sys.modules['__main__']
            loader.load(ns.__dict__, preserve={'print_banner', '_orig_stdout', '_orig_stderr'})

        else:
            logging.warning("{:s} : Skipping the reset of the primary namespace as \"{:s}\" was not found in Python's module list.".format(self.wanted_name, '__main__'))

        # We don't bother tampering with the user's namespace, since technically
        # we don't have access to it.. However, we'll still try to install the
        # necessary hooks or other features depending what we found available.
        ok = True
        try:
            import internal, hooks

        except (ImportError, Exception):
            logging.critical("{:s} : An error occurred while trying to import the necessary modules \"{:s}\", and \"{:s}\".".format(self.wanted_name, 'internal', 'hooks'), exc_info=True)
            ok = False

        try:
            ok and internal.interface

        except AttributeError:
            logging.critical("{:s} : One of the internal modules, \"{:s}\", is critical but was not properly loaded.".format(self.wanted_name, '.'.join(['internal', 'interface'])))

        # Check to see if our notification instance was assigned into idaapi. If
        # it wasn't then try to construct one and assign it for usage.
        try:
            if ok and not hasattr(idaapi, '__notification__'):
                idaapi.__notification__ = notification = internal.interface.prioritynotification()

        except Exception:
            logging.warning("{:s} : An error occurred while trying to instantiate the notifications interface. Notifications will be left as disabled.".format(self.wanted_name))

        # Check to see if all is well, and if it is then we can proceed to install
        # the necessary hooks to kick everything off.
        if ok:
            logging.info("{:s} : Plugin has been successfully initialized and will now start attaching to the necessary handlers.".format(self.wanted_name))
            hooks.make_ida_not_suck_cocks(idaapi.NW_INITIDA)
            self.state = 'local'

        else:
            logging.warning("{:s} : Due to previous errors the plugin was not properly attached. Modules may still be imported, but a number of features will not be available.".format(self.wanted_name))
            self.state = 'disabled'

        return idaapi.PLUGIN_KEEP

    def term(self):
        if self.state is None:
            logging.warning("{:s} : Ignoring the host application request to terminate as the plugin has not yet been initialized.".format(self.wanted_name))
            return

        # Figure out how we were started so that we can slowly tear things down.
        if self.state in {'disabled', 'persistent'}:
            logging.debug("{:s} : Host application requested termination of {:s} plugin.".format(self.wanted_name, self.state))
            return

        # We were run locally, so we're only allowed to interact with the current
        # database. This means that we now will need to shut everything down.
        try:
            import internal, hooks

        except ImportError:
            logging.critical("{:s} : An error occurred while trying to import the necessary modules \"{:s}\", and \"{:s}\" during plugin termination.".format(self.wanted_name, 'internal', 'hooks'), exc_info=True)
            return

        # Now we can just remove our hooks and all should be well.
        try:
            logging.debug("{:s} : Detaching from the host application as requested.".format(self.wanted_name))
            hooks.make_ida_suck_cocks(idaapi.NW_TERMIDA)

        except Exception:
            logging.critical("{:s} : An error occurred while trying to detach from the host application during plugin termination. Application may become unstable.".format(self.wanted_name), exc_info=True)
        return

    def run(self, args):
        import ui

        # Shove some help down the user's throat.
        print("Python>{:<{:d}s} # Use `help({:s})` for usage".format('ui.keyboard.list()', 40, 'ui.keyboard'))
        try:
            ui.keyboard.list()
        except Exception as E:
            print(E)
        print('')

        # Have some more...
        hooks = [name for name in dir(ui.hook) if not name.startswith('__')]
        print('The following hook types are locked and loaded:' if hooks else 'Currently no hooks have been initialized.')
        for name in hooks:
            item = getattr(ui.hook, name)
            fullname = '.'.join(['ui.hook', name])
            print("Python>{:<{:d}s} # Use `help({:s})` for usage and `{:s}.list()` to see availability".format(fullname, 40, fullname, fullname))
            print(item)
            print('')

        # Dead leaves on the dirty ground...when I know you're not around. Shiny
        # tops and soda pops, when I hear you make a sound.

        noise = '''Welcome to the IDA-minsc plugin. My arrow keys are broken.

        This plugin is (mostly) a library that aims to simplify IDAPython. However,
        it utilizes hooks and keyboard shortcuts in a variety of ways in order to
        keep track of the changes that the user may make within their database.

        Essentially the goal of this plugin is to make absolutely _everything_
        that a user may notate in their database serializeable (into a python type)
        and queryable so that things can be exchanged with other Python interpreters.

        Use "." to jump to the command-line and Shift+F2 if you need multi-line.
        Don't forget `dir()` to look around, and `help(thing)` to inquire.
        '''

        # If you can hear a piano fall, you can hear me coming down the hall. If
        # I can just hear your pretty voice, I don't think I need to see at all.

        home = os.path.expanduser('~')
        dotfile = "On startup, the {:s} file will be executed within the primary namespace.".format(os.path.join(home, '.idapythonrc.py'))

        # Every breath that is in your lungs is a tiny little gift to me.

        import database
        path = os.path.join(database.config.path() or '$IDB_DIRECTORY', 'idapythonrc.py')
        rcfile = "Upon {:s} database, the {:s} file will be loaded.".format('opening up the current' if database.config.path() else 'opening up a', os.path.abspath(path))
        ui.message('\n'.join([noise, '\n'.join([dotfile, rcfile])]))
        return

def PLUGIN_ENTRY():
    return MINSC()
