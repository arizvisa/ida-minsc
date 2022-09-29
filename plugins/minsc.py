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
import builtins, six, imp, fnmatch, ctypes, itertools, types
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

    def iterate_api(self, include='*.py', exclude=None, **attributes):
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

    def __iter__(self):
        '''Yield the full path of each module that is provided by this class.'''
        return
        yield

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

    def __iter__(self):
        '''Yield each of the available modules.'''
        for name, _ in self.iterate_api(**self.attrs):
            yield name
        return

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
        maximum = max(map(len, cache)) if cache else 0
        documentation = '\n'.join("{:<{:d}s} : {:s}".format(name, maximum, path) for name, path in sorted(cache.items()))
        documentation = '\n\n'.join([self.attrs['__doc__'], documentation]) if '__doc__' in self.attrs else documentation
        module.__doc__ = documentation

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
                logging.debug("{:s} : Error trying to import module `{:s}` from {!s}. Queuing it until later.".format(self.__name__, name, path), exc_info=True)

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
        # are considered non-fatal because importing another sub-module helped resolve it.
        import logging
        for name, exc_info in result.items():
            logging.info("{!s} : Encountered a non-fatal exception while trying to import recursive module `{:s}` from {!s}".format(self.__name__, name, cache[name]), exc_info=result[name])

        # Return the module that we just created.
        return module

    def __iter__(self):
        '''Yield each of the available modules.'''
        for name, _ in self.iterate_api(**self.attrs):
            yield name
        return

class internal_object(object):
    """
    Loader class which will simply expose an object instance as the module.
    """
    sys = sys

    def __init__(self, module, constructor, *args, **attributes):
        '''Initialize the loader so that it returns the object generated by `constructor` when the module `name` is requested.'''
        self.__name__, self.__object__ = module, None
        self.__constructor__ = constructor, args, attributes

    def find_module(self, fullname, path=None):
        '''If the module being searched for matches our `fullname`, then act as its loader.'''
        return self if path is None and fullname == self.__name__ else None

    def new_instance(self):
        '''Create a new instance of the backing object for the module loaded by this finder.'''
        callable, args, attributes = self.__constructor__
        instance = callable(*args)
        for name, value in attributes.items():
            try: setattr(instance, name, value)
            except: continue
        return instance

    def get_instance(self):
        '''Return the backing object for the module loaded by this finder.'''
        instance = self.new_instance() if self.__object__ is None else self.__object__
        self.__object__ = instance
        return instance

    def reload_module(self):
        '''Reload (re-instantiate) the backing object for the module loaded by this finder.'''
        res = self.__object__
        self.__object__ = self.new_instance()
        return res

    def load_module(self, fullname):
        '''Return the specific object for the module specified by `fullname`.'''
        if fullname != self.__name__:
            raise ImportError("object-loader ({:s}) was not able to find a module named `{:s}`".format(self.__name__, fullname))
        module = self.sys.modules[fullname] = self.get_instance()
        return module

class object_proxy(object):
    """
    This class is responsible for generating a proxy type that
    can be used to access attributes from a completely different
    object.

    Upon using this class, two objects will be returned. The first
    object is an instance of the proxy object that may be accessed
    and used as the object that is being proxied. The second object
    that is returned is a coroutine that can be used to switch the
    backing for the proxy object to a different type.
    """
    class reference(object):
        __slots__ = {'object'}

    class attributes(object):
        """
        This properties within this namespace contains an unordered list
        of properties that may be used or ignored when copying or removing
        attributes from an object into a proxy object.
        """
        description = {'__module__', '__name__', '__doc__'}
        ignored = {'__class__', '__dict__', '__weakref__'}
        required = {'__eq__', '__ne__', '__hash__', '__str__', '__repr__', '__unicode__'}

        klass = {key for key, value in itertools.chain(object.__dict__.items(), type.__dict__.items()) if callable(value)} | ignored
        instance = (lambda klass=klass: {key for key in dir(object()) if key not in klass})() | ignored

    def __new__(cls, module, name):
        mutable_t = type('|strongref|', tuple(subclass for subclass in cls.reference.__subclasses__()), {key : None for key, value in cls.reference.__dict__.items() if key in cls.reference.__slots__})
        if module:
            mutable_t.__module__ = module
        mutable = mutable_t()

        # create a proxy_t and instantiate it before passing it to the updater.
        proxy_t = cls.proxy(mutable, name)
        updater = cls.proxy_updater(mutable, proxy_t)

        # now we can initialize the updater coroutine to return the proxy from its
        # first yielded result, and return the coroutine to allow updating the proxy.
        return next(updater), updater

    @classmethod
    def proxy_updater(cls, mutable, proxy_t):
        '''This coroutine is responsible for synchronizing the `mutable` object with any of the objects that it receives and updating the documentation for `proxy_t`.'''
        state = {key : getattr(proxy_t, key) for key in dir(proxy_t) if hasattr(proxy_t, key)}
        C = cls.update_none(proxy_t)
        backing = proxy = next(C)
        while True:
            backing = (yield backing)
            C.close()

            # First thing we need to do is to update our mutable instance
            # to reference the backing type that we received.
            mutable.object = backing

            # Figure out which updater we need to use for the backing object.
            if isinstance(backing, types.FunctionType):
                C = cls.update_callable(proxy_t)
            elif isinstance(backing, object):
                #C = cls.update_object(proxy_t, proxy)
                C = cls.update_class(proxy_t)
            elif isinstance(backing, types.ModuleType):
                raise TypeError(backing)
                C = cls.update_module(proxy)
            else:
                raise TypeError(backing)

            # Start the updater that we determined and proceed to update our proxy object.
            state = next(C)
            C.send(backing)
            C.send(backing)
            C.send(backing)
        return

    @classmethod
    def proxy(cls, mutable, name, **attributes):
        """Return a new modifiable type of the given `name` that proxies all attribute access to the instance provided by `mutable`.

        If any `attributes` are given, then use the given attribute instead of the `backing` instance.
        """
        def __getattribute__(attribute):
            '''This method proxies all attribute fetches to an inaccessible backing object.'''
            return attributes[attribute] if attribute in attributes else object.__getattribute__(mutable.object, attribute)

        def __setattribute__(attribute, value):
            '''This method proxies all attribute assignments to an inaccessible backing object.'''
            try:
                object.__setattr__(mutable.object, attribute, value)
            except AttributeError:
                attributes[attribute] = value
            return

        def __delattr__(attribute):
            '''This method proxies all attribute removals to an inaccessible backing object.'''
            attributes.pop(attribute) if attribute in attributes else delattr(mutable.object, attribute)

        namespace = {'__getattribute__': __getattribute__, '__setattr__': __setattribute__, '__delattr__': __delattr__}
        return type(name, (object,), {key : staticmethod(value) for key, value in namespace.items()})

    @classmethod
    def update_none(cls, proxy_t):
        '''This coroutine is a dummy coroutine that uses `proxy_t` to construct an object and yield it during initialization.'''
        yield proxy_t()
        while True:
            (yield)
        return

    @classmethod
    def update_class(cls, proxy):
        '''This coroutine is responsible for updating the documentation of the provided `proxy` (class) with the attributes belonging to the object (class) that is received.'''
        state = {}
        object = (yield state)

        # collect all of the attributes from the class belonging to the object
        # we received while including any of our description-related attributes.
        state.update({key : value for key, value in object.__class__.__dict__.items() if key not in cls.attributes.klass})
        state.update({key : getattr(object.__class__, key, None) for key in cls.attributes.description})

        # FIXME: the attributes in `cls.attributes.required` may already be defined,
        #        in our backing object but we're not yet copying them into our proxy
        #        type since they might be a builtin that inherits from object.

        # before we apply any of the state to the proxy, yield as a sort-of
        # breakpoint to allow the caller to tamper with the state if necessary.
        try:
            (yield)

            # now we can update the proxy atributes we snagged and spin
            # until the user decides to close us.
            [setattr(proxy, key, value) for key, value in state.items() if key not in cls.attributes.description]
            [setattr(proxy, key, state[key]) for key in cls.attributes.description if state.get(key, None) is not None]

            while True: (yield)

        # remove any and all attributes that we added to the proxy's class.
        finally:
            [delattr(proxy, key) for key in state if key not in cls.attributes.description]
        state.clear()

    @classmethod
    def update_instance(cls, proxy):
        '''This coroutine is responsible for updating the documentation of the provided `proxy` with the attributes belonging to the object that is received.'''
        state = {}
        object = (yield state)

        # preserve all attributes and any description attributes for the instance
        # of the object that we're trying to mirror.
        state.update({key : value for key, value in object.__dict__.items() if key not in cls.attributes.instance})
        state.update({key : getattr(object.__class__, key, None) for key in cls.attributes.description})
        #[state.pop(key, None) for key, value in proxy.__class__.__dict__.items() if key in state and value == state[key]]

        # then we yield in order to give the caller a chance to tamper or display
        # the state if they feel it's absolutely necessary.
        try:
            (yield)

            # update the proxy with the non-description attributes we collected.
            updates = {key : value for key, value in state.items() if key not in cls.attributes.description}
            [setattr(proxy, key, value) for key, value in updates.items()]

            # then update the proxy with the description attributes if any are available.
            descriptions = {key : state.get(key, None) for key in cls.attributes.description}
            for key, value in {attribute : state.pop(attribute, None) for attribute in cls.attributes.description}.items():
                if value:
                    setattr(proxy, key, value)
                continue

            # once we're done spin until the user decides they're ready to close us.
            while True: (yield)

        # delete all the attributes that are non-description. non-description attributes
        # are non-removable which is why we skip over them entirely.
        finally:
            [delattr(proxy, key) for key in state if key not in cls.attributes.description]
        state.clear()

    @classmethod
    def update_callable(cls, proxy):
        '''This coroutine is responsible for updating the documentation of the provided `proxy` with the attributes belonging to the callable that is received.'''
        state = {}
        callable = (yield state)

        # callables will require us to associate it as a staticmethod to discard
        # the first parameter, and include each of its description attributes
        state['__call__'] = staticmethod(callable)
        state.update({key : getattr(callable, key, None) for key in cls.attributes.description})

        # pydoc._getowndoc will refuse to return documentation if `proxy.__doc__` is the same
        # as `type(proxy).__doc__`. Of course, this is always true because we're forwarding
        # all attribute fetches to the backing type which makes this object look completely
        # like a function. to deal with this, we promote __doc__ to a property so it doesn't match.
        if '__doc__' in state:
            state['__doc__'] = property(fget=lambda _, __doc__=state['__doc__']: __doc__)

        # yield to give the caller a chance to mess with the state and
        # act similarly to the other updater implementations.
        try:
            (yield)

            # now we update the proxy, and spin until the caller is done.
            [setattr(proxy, key, value) for key, value in state.items() if value is not None]
            while True: (yield)

        # afterwards we can just undo the attributes we attached.
        finally:
            [delattr(proxy, key) for key, value in state.items() if key not in cls.attributes.description]
        state.clear()

    @classmethod
    def update_object(cls, proxy_t, proxy):
        '''This coroutine is responsible for updating the documentation of the provided `proxy` by combining the implementations of `update_class` and `update_instance`.'''
        state = {}

        # Create our coroutines for both the class and proxy, and set them off.
        Cclass, Cinstance = cls.update_class(proxy), cls.update_instance(proxy)
        Sclass, Sinstance = (next(C) for C in [Cclass, Cinstance])
        [state.update(S) for S in [Sclass, Sinstance]]

        # Now we receive the object from the user so we can send it to both
        # coroutines that we've just started up.
        object = (yield state)
        [C.send(object) for C in [Cclass, Cinstance]]

        # Now we can just spin indefinitely while ensuring that we cycle both
        # coroutines to update the state we yielded to the caller.
        try:
            while True:
                (yield)
                [next(C) for C in [Cclass, Cinstance]]
                [state.update(S) for S in [Sclass, Sinstance]]

        finally:
            pass
        return

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

    documentation = 'This is a ctypes-library to the shared object that is exposed to the IDA SDK.'

    # IDA's native lower-level api
    if sys.platform in {'darwin'}:
        yield internal_object('ida', library, idaapi.idadir("libida{:s}.dylib".format('' if idaapi.BADADDR < 0x100000000 else '64')), __name__='IDA', __doc__=documentation)

    elif sys.platform in {'linux', 'linux2'}:
        yield internal_object('ida', library, idaapi.idadir("libida{:s}.so".format('' if idaapi.BADADDR < 0x100000000 else '64')), __name__='IDA', __doc__=documentation)

    elif sys.platform in {'win32'}:
        if os.path.exists(idaapi.idadir('ida.wll')):
            yield internal_object('ida', library, idaapi.idadir('ida.wll'), __name__='IDA', __doc__=documentation)
        else:
            yield internal_object('ida', library, idaapi.idadir("ida{:s}.dll".format('' if idaapi.BADADDR < 0x100000000 else '64')), __name__='IDA', __doc__=documentation)

    else:
        logging.warning("{:s} : Unable to load IDA's native api via ctypes. Ignoring...".format(__name__))

    # private (internal) api
    documentation = 'This virtual module contains a number of internal submodules.'
    yield internal_submodule('internal', os.path.join(root, 'misc'), __doc__=documentation)

    # public (hooking) api
    yield internal_object('hook', lambda: __import__('internal').hooks.module(), __name__='hook')

    # public api
    yield internal_path(os.path.join(root, 'base'))

    # tools and application api
    documentation = 'This virtual module contains a number of different files as submodules.'
    for directory in ['tools', 'application']:
        yield internal_submodule(directory, os.path.join(root, directory), __doc__=documentation)
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
            contents = "{:#0{:d}x}".format(item.value, 2 + 2 * size) if isinstance(item.value, six.integer_types) else "{!s}".format(item.value)
            storage.append("{:s}({:s})".format(cls.__name__, contents))

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
        builtins._ = item
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

# Locate the user's dotfile and execute it within the specified namespace.
def dotfile(namespace, filename=u'.idapythonrc.py'):
    '''Execute the user's dotfile within the specified namespace.'''
    path = None

    # A closure that just consumes paths until it finds one that
    # it can read and execute it within the specified namespace.
    def read_and_execute(filename, namespace):
        path = (yield)
        while True:
            fp = os.path.join(path, filename)
            try:
                with open(fp, 'r') as infile:
                    content = infile.read()
            except IOError:
                logging.debug("{:s} : Error reading the dotfile at `{!s}`.".format(__name__, fp), exc_info=True)
            else:
                break
            path = (yield)

        exec(content, namespace)

    # Another closure that just tries to determine the user's home
    # directory from the environment variables it receives.
    def find_home(*variables):
        iterable = (var for var in variables if os.getenv(var, default=None) is not None)
        path = next(iterable, None)
        if path is None:
            raise OSError("{:s} : Unable to determine the user's home directory from the environment.".format(__name__))
        return path, os.getenv(path)

    # Create our coroutine, initialize it, and then feed it some paths.
    tribulations = read_and_execute(filename, namespace); next(tribulations)

    try:
        path = os.path.expanduser('~')
        tribulations.send(path)

        var, path = find_home('HOME', 'USERPROFILE')
        tribulations.send(path)

    # If we stopped, then it was read and executed successfully.
    except StopIteration:
        logging.debug("{:s} : Successfully read and executed the dotfile at `{!s}`.".format(__name__, os.path.join(path, filename)))

    # If we received an OSError, then this likely happened while we
    # were trying to find the home directory. Pass it to the user.
    except OSError as E:
        print(E)

    # Any other exception is because of an issue in the user's script,
    # so we'll do our best to log the backtrace for them to debug.
    except Exception:
        logging.warning("{:s} : Unexpected exception raised while trying to execute the dotfile at `{!s}`.".format(__name__, os.path.join(path, filename)), exc_info=True)

    # If we didn't get an exception, then literally we couldn't find
    # any file that we were supposed to execute. Log it and move on.
    else:
        vowels, alpha = tuple('aeiou'), next((filename[index:] for index, item in enumerate(filename.lower()) if item in 'abcdefghijklmnopqrstuvwxyz'), filename)
        logging.warning("{:s} : Unable to locate a{:s} {:s} dotfile in the user's {:s} directory ({!s}).".format(__name__, 'n' if alpha.startswith(vowels) else '', filename, var, path))
    finally:
        tribulations.close()

    # Verify that executing the dotfile did not add the root directory
    # to the system path because the contents of the root directory is
    # explicitly handled by our loaders.
    busted = [(index, item) for index, item in enumerate(sys.path) if os.path.realpath(item) in {os.path.realpath(root)}]
    if busted:
        logging.warning("{:s} : Execution of `{!s}` has resulted in a conflict between the repository path ({!r}) and the system path.".format(__name__, filename, root))
        [ logging.warning("{:s} : The system path at index {:d} ({!r}) resolves to {!r} which conflicts with the plugin and may interfere with imports.".format(__name__, index, item, os.path.realpath(item))) for index, item in busted ]
    return

# The following logic is actually responsible for starting up the whole
# plugin. This is done with by trying with a notification, falling back
# to a timer, and then straight-up executing things if all else fails.
def startup(namespace=None):
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
        logging.critical("{:s} : An error occured while trying to import the \"{:s}\" module.".format(__name__, 'internal'), exc_info=True)
        raise SystemError("{:s} : Unable to start up plugin without being able to access its \"{:s}\" modules.".format(__name__, 'internal'))

    except AttributeError:
        logging.critical("{:s} : An error occured while trying to access the \"{:s}\" module.".format(__name__, '.'.join(['internal', 'interface'])))
        raise SystemError("{:s} : Unable to start up plugin due to an error while loading its \"{:s}\" modules.".format(__name__, 'internal'))

    # Finally we can construct our priority notification class and inject it into
    # the IDAPython module. This object needs to exist in order for everything to
    # initialize and deinitialize properly.
    idaapi.__notification__ = notification = internal.interface.prioritynotification()

    # Now we can proceed to install our hooks that actually initialize and uninitialize
    # MINSC. We define two closures here (with documentation) because these are actually
    # accessible by the user if they navigate the hook interface that we expose to them.
    def execute_user_dotfile(*args, **kwargs):
        '''This function is responsible for executing the dotfile in the home directory of the user.'''
        return dotfile(namespace)

    # This second closure is meant to be called from a timer. To avoid having to register
    # multiple timers, we pack up our logic that loads the plugin and the user's dotfile
    # within a single function to register.
    def load_plugin_and_execute_user_dotfile(*args, **kwargs):
        '''This function is responsible for loading the plugin and executing the dotfile in the home directory of the user.'''
        result = internal.hooks.ida_is_busy_sucking_cocks(*args, **kwargs)
        dotfile(namespace)
        return result

    # Before we attempt to use the hooks, though, we first check if we can access
    # the hooks since they are pretty critical for all of our startup logic.
    try:
        import internal
        internal.hooks

    # If we couldn't access the hooks, then we can still proceed but as a typical
    # set of importable python modules. Log a warning and try the user's dotfile.
    except AttributeError:
        logging.warning("{:s} : An error occured while trying to access the \"{:s}\" module which will result in missing features.".format(__name__, '.'.join(['internal', 'hooks'])))
        namespace and dotfile(namespace)
        return

    # Finally we can register the functions that will actually be responsible for
    # initializing the plugin. If we were given a namespace, then we can register
    # our closure that loads the user's dotfile too.
    try:
        notification.add(idaapi.NW_INITIDA, internal.hooks.make_ida_not_suck_cocks, -1000)
        namespace and notification.add(idaapi.NW_INITIDA, execute_user_dotfile, 0)

    # If installing that hook failed, then check if we're running in batch mode. If
    # we are, then just immediately register things and load the user dotfile.
    except Exception:
        TIMEOUT = 5
        if idaapi.cvar.batch:
            internal.hooks.ida_is_busy_sucking_cocks()
            namespace and dotfile(namespace)

        # Otherwise warn the user about this and register our hook with a timer.
        elif namespace is None:
            logging.warning("{:s} : Unable to add a notification via `{:s}` for {:s}({:d}).".format(__name__, '.'.join(['idaapi', 'notify_when']), '.'.join(['idaapi', 'NW_INITIDA']), idaapi.NW_INITIDA))
            logging.warning("{:s} : Registering {:.1f} second timer with `{:s}` in an attempt to load plugin...".format(__name__, TIMEOUT, '.'.join(['idaapi', 'register_timer'])))
            idaapi.register_timer(TIMEOUT, internal.hooks.ida_is_busy_sucking_cocks)
            six.print_('=' * 86)

        # If we were given a namespace to load into, then we register the closure
        # that we defined into the timer so that the user's dotfile gets executed.
        else:
            logging.warning("{:s} : Unable to add a notification via `{:s}` for {:s}({:d}).".format(__name__, '.'.join(['idaapi', 'notify_when']), '.'.join(['idaapi', 'NW_INITIDA']), idaapi.NW_INITIDA))
            logging.warning("{:s} : Registering {:.1f} second timer with `{:s}` in an attempt to load plugin...".format(__name__, TIMEOUT, '.'.join(['idaapi', 'register_timer'])))
            idaapi.register_timer(TIMEOUT, load_plugin_and_execute_user_dotfile)
            six.print_('=' * 86)
        del(TIMEOUT)

    # If we were able to hook NW_INITIDA, then the NW_TERMIDA hook should also work.
    else:
        try:
            notification.add(idaapi.NW_TERMIDA, internal.hooks.make_ida_suck_cocks, +1000)

        # Installing the termination hook failed, but it's not really too important...
        except Exception:
            logging.warning("{:s} : Unable to add a notification for idaapi.NW_TERMIDA({:d}).".format(__name__, idaapi.NW_TERMIDA))
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
            module = imp.load_source("{:s}__loader__".format(__name__), filename)

        except IOError:
            logging.critical("{:s} : A critical error occurred while trying to read the plugin loader from the file: {:s}".format(__name__, filename), exc_info=True)

        except ImportError:
            logging.critical("{:s} : A critical error occurred while initializing the plugin loader in \"{:s}\"".format(__name__, filename), exc_info=True)

        except Exception:
            logging.critical("{:s} : A critical error occurred while initializing the plugin loader".format(__name__, filename), exc_info=True)

        return module

    def init(self):
        version = getattr(idaapi, '__version__', None)

        # Check our version.. but not really. We're only checking it to see
        # whether the plugin has been loaded yet. If our version if a float,
        # then our module finders have already been loaded and we just need
        # to persist ourselves.
        if isinstance(version, float):
            self.state = self.__class__.state = 'persistent'
            return idaapi.PLUGIN_KEEP

        # If our state is already initialized, then we've done this before.
        elif self.state:
            logging.critical("{:s} : Loading plugin again despite it already being initialized ({:s}).".format(__name__, self.state))

        # Now the version hasn't been assigned yet, then the user didn't
        # install this globally. This means that we don't control the primary
        # namespace. So we'll need to load ourselves still and then afterwards
        # we can uninstall ourselves whenever our plugin is asked to terminate.
        loader = self.get_loader()
        if not loader:
            raise SystemError("{:s} : Unable to get the loader required by the plugin.".format(__name__))

        # Iterate through all of the items in our system path in order to remove
        # any that reference our plugin root. This is because we're using our
        # own loaders to find modules instead of Python's file loaders.
        sys.path[:] = [item for item in sys.path if os.path.realpath(item) not in {os.path.realpath(root)}]

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
            logging.warning("{:s} : Skipping installation of the display hook at \"{:s}\" due to a lack of awareness about the current one ({!r}).".format(__name__, '.'.join(['sys', 'displayhook']), sys.displayhook))

        # Now we'll try and tamper with the user's namespace. We'll search through
        # Python's module list, and if we find it we'll just swap it out for root.
        if '__main__' in sys.modules:
            ns, banner_required = sys.modules['__main__'], {'print_banner', 'IDAPYTHON_VERSION', 'sys'}
            loader.load(ns.__dict__, preserve={'_orig_stdout', '_orig_stderr'} | banner_required)
            hasattr(ns, 'print_banner') and ns.print_banner()
            [ns.__dict__.pop(item, None) for item in banner_required]

        else:
            logging.warning("{:s} : Skipping the reset of the primary namespace as \"{:s}\" was not found in Python's module list.".format(__name__, '__main__'))

        # We don't bother tampering with the user's namespace, since technically
        # we don't have access to it.. However, we'll still try to install the
        # necessary hooks or other features depending what we found available.
        ok = True
        try:
            import internal

        except (ImportError, Exception):
            logging.critical("{:s} : An error occurred while trying to import the critical \"{:s}\" module.".format(__name__, 'internal'), exc_info=True)
            ok = False

        try:
            ok and internal.hooks

        except AttributeError:
            logging.warning("{:s} : One of the internal modules, \"{:s}\" was not properly loaded and may result in some missing features.".format(__name__, '.'.join(['internal', 'hooks'])))
            ok = False

        try:
            ok and internal.interface

        except AttributeError:
            logging.critical("{:s} : One of the internal modules, \"{:s}\", is critical but was unable to be loaded.".format(__name__, '.'.join(['internal', 'interface'])))

        # Check to see if our notification instance was assigned into idaapi. If
        # it wasn't then try to construct one and assign it for usage.
        try:
            if ok and not hasattr(idaapi, '__notification__'):
                idaapi.__notification__ = notification = internal.interface.prioritynotification()

        except Exception:
            logging.warning("{:s} : An error occurred while trying to instantiate the notifications interface. Notifications will be left as disabled.".format(__name__))

        # Check to see if all is well, and if it is then we can proceed to install
        # the necessary hooks to kick everything off.
        if ok:
            logging.info("{:s} : Plugin has been successfully initialized and will now start attaching to the necessary handlers.".format(__name__))
            self.state = self.__class__.state = 'local'
            internal.hooks.make_ida_not_suck_cocks(idaapi.NW_INITIDA)

            # If there's an accessible "__main__" namespace, then dump the dotfile into it.
            '__main__' in sys.modules and dotfile(sys.modules['__main__'].__dict__)

        else:
            logging.warning("{:s} : Due to previous errors the plugin was not properly attached. Modules may still be imported, but a number of features will not be available.".format(__name__))
            self.state = self.__class__.state = 'disabled'

        return idaapi.PLUGIN_KEEP

    def term(self):
        if self.state is None:
            logging.warning("{:s} : Ignoring the host application request to terminate as the plugin has not yet been initialized.".format(__name__))
            return

        # Figure out how we were started so that we can slowly tear things down.
        if self.state in {'disabled', 'persistent'}:
            logging.debug("{:s} : Host application requested termination of {:s} plugin.".format(__name__, self.state))
            return

        # We were run locally, so we're only allowed to interact with the current
        # database. This means that we now will need to shut everything down.
        try:
            import internal, hooks

        except ImportError:
            logging.critical("{:s} : An error occurred while trying to import the necessary modules \"{:s}\", and \"{:s}\" during plugin termination.".format(__name__, 'internal', 'hooks'), exc_info=True)
            return

        # Now we can just remove our hooks and all should be well.
        try:
            logging.debug("{:s} : Detaching from the host application as requested.".format(__name__))
            hooks.make_ida_suck_cocks(idaapi.NW_TERMIDA)

        except Exception:
            logging.critical("{:s} : An error occurred while trying to detach from the host application during plugin termination. Application may become unstable.".format(__name__), exc_info=True)
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
