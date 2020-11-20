"""
Internal initialization script

This is an internal script that is executed when IDA starts. Things
such as meta_path hooks, replacing the namespace with the contents
of the __root__ module, and implementing a work-around for the hack
that IDAPython does with saving the contents of sys.modules. After
initializing everything, this script will then hand off execution
to the user's idapythonrc.py in their home directory.
"""

# output the IDAPython banner when IDA starts
print_banner()

# some general python modules that we use for meta_path
import sys, os
import imp, fnmatch, ctypes, types
import idaapi

library = ctypes.WinDLL if os.name == 'nt' else ctypes.CDLL

# grab ida's user directory and remove from path since we use meta_path to locate api modules
root = idaapi.get_user_idadir()
sys.path.remove(root)

class internal_api(object):
    """Meta-path base-class for an api that's based on files within a directory"""
    os, imp, fnmatch = os, imp, fnmatch
    def __init__(self, directory, **attributes):
        self.path = self.os.path.realpath(directory)
        [ setattr(self, name, attribute) for name, attribute in attributes.items() ]

    ### Api operations
    def load_api(self, path):
        path, filename = self.os.path.split(path)
        name, _ = self.os.path.splitext(filename)
        return self.imp.find_module(name, [ path ])

    def iterate_api(self, include='*.py', exclude=None):
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
        file, path, description = self.load_api(path)
        try:
            return self.imp.load_module(modulename, file, path, description)
        finally: file.close()

    ### Module operations
    def new_module(self, fullname, doc=None):
        res = self.imp.new_module(fullname)
        res.__package__ = fullname
        res.__doc__ = doc or ''
        return res

    def find_module(self, fullname, path=None):
        raise NotImplementedError

    def load_module(self, fullname):
        raise NotImplementedError

class internal_path(internal_api):
    def __init__(self, path, **attrs):
        super(internal_path, self).__init__(path)
        attrs.setdefault('include', '*.py')
        self.attrs, self.cache = attrs, { name : path for name, path in self.iterate_api(**attrs) }

    def find_module(self, fullname, path=None):
        return self if path is None and fullname in self.cache else None

    def load_module(self, fullname):
        self.cache = { name : path for name, path in self.iterate_api(**self.attrs) }
        return self.new_api(fullname, self.cache[fullname])

class internal_submodule(internal_api):
    sys = sys
    def __init__(self, __name__, path, **attrs):
        super(internal_submodule, self).__init__(path)
        attrs.setdefault('include', '*.py')
        self.__name__, self.attrs = __name__, attrs

    def find_module(self, fullname, path=None):
        return self if path is None and fullname == self.__name__ else None

    def filter_module(self, filename):
        return self.fnmatch.fnmatch(filename, self.attrs['include']) and ('exclude' in self.attrs and not self.fnmatch.fnmatch(filename, self.attrs['exclude']))

    def fetch_module(self, name):
        cache = { name : path for name, path in self.iterate_api(**self.attrs) }
        return self.new_api(name, cache[name])

    def new_api(self, modulename, path):
        cls, fullname = self.__class__, '.'.join([self.__name__, modulename])
        res = super(cls, self).new_api(fullname, path)
        res.__package__ = self.__name__
        return res

    def load_module(self, fullname):
        module = self.sys.modules[fullname] = self.new_module(fullname)
        # FIXME: make module a lazy-loaded object for fetching module-code on-demand

        cache = { name : path for name, path in self.iterate_api(**self.attrs) }
        module.__doc__ = '\n'.join("{:s} -- {:s}".format(name, path) for name, path in sorted(cache.items()))

        for name, path in cache.items():
            try:
                res = self.new_api(name, path)
                modulename = '.'.join([res.__package__, name])

            except Exception:
                __import__('logging').warn("{:s} : Unable to import module {:s} from {!r}".format(self.__name__, name, path), exc_info=True)

            else:
                setattr(module, name, res)
            continue
        return module

class internal_object(object):
    def __init__(self, __name__, object):
        self.__name__, self.object = __name__, object

    def find_module(self, fullname, path=None):
        return self if path is None and fullname == self.__name__ else None

    def load_module(self, fullname):
        if fullname != self.__name__:
            raise ImportError("Loader {:s} was not able to find a module named {:s}".format(self.__name__, fullname))
        return self.object

class plugin_module(object):
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

## ida's native api
if sys.platform == 'darwin':
    sys.meta_path.append( internal_object('ida', library(idaapi.idadir('libida.dylib'))) )
elif sys.platform in 'linux2':
    sys.meta_path.append( internal_object('ida', library('libida.so')) )
elif sys.platform == 'win32':
    if __import__('os').path.exists(idaapi.idadir('ida.wll')):
        sys.meta_path.append( internal_object('ida', library(idaapi.idadir('ida.wll'))) )
    elif idaapi.BADADDR >= 0x100000000:
        sys.meta_path.append( internal_object('ida', library(idaapi.idadir("ida{:s}.dll".format("64")))) )
    else:
        sys.meta_path.append( internal_object('ida', library(idaapi.idadir("ida{:s}.dll".format("")))) )
else:
    raise NotImplementedError

# private api
sys.meta_path.append( internal_submodule('internal', os.path.join(root, 'base'), include='_*.py') )

# public api
sys.meta_path.append( internal_path(os.path.join(root, 'base'), exclude='_*.py') )
sys.meta_path.append( internal_path(os.path.join(root, 'misc')) )

# user and application api's
for _ in ('custom', 'app'):
    sys.meta_path.append( internal_submodule(_, os.path.join(root, _)) )

# temporarily root namespace
__root__ = imp.load_source('__root__', os.path.join(root, '__root__.py'))

# empty out idapython's namespace
map(globals().pop, {_ for _ in globals().copy().viewkeys() if not _.startswith('__')})

# re-populate with a default namespace and empty out our variable
globals().update({_ for _ in __root__.__dict__.viewitems() if not _[0].startswith('__')})
globals().pop('__root__')

# try and execute our user's idapythonrc.py
try:
    try:
        # execute user's .pythonrc and .idapythonrc in one go
        if __import__('user').home:
            execfile(__import__('os').path.join(__import__('user').home, '.idapythonrc.py'))

    except ImportError:
        # otherwise try to figure it out without tainting the namespace
        if __import__('os').getenv('HOME', default=None) is not None:
            execfile(__import__('os').path.join(__import__('os').getenv('HOME'), '.idapythonrc.py'))
        elif __import__('os').getenv('USERPROFILE', default=None) is not None:
            execfile(__import__('os').path.join(__import__('os').getenv('USERPROFILE'), '.idapythonrc.py'))
        else:
            raise OSError('Unable to determine the user\'s home directory.')
        pass

except IOError:
    __import__('logging').warn('No .idapythonrc.py file found in the user\'s home directory.')

except Exception, e:
    print("Unexpected exception raised while trying to execute `~/.idapythonrc.py`.")
    __import__('traceback').print_exc()

## stupid fucking idapython hax
# prevent idapython from trying to write its banner to the message window since we called it up above.
print_banner = lambda: None

# find the frame that fucks with our sys.modules, and save it for later
_ = __import__('sys')._getframe()
while _.f_code.co_name != 'IDAPython_ExecScript':
    _ = _.f_back

# inject our current sys.modules state into IDAPython_ExecScript's state if it's the broken version
if 'basemodules' in _.f_locals:
    _.f_locals['basemodules'].update(__import__('sys').modules)
del _
