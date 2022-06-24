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

# grab ida's user directory and remove from path since we use meta_path to all
# of our modules. we also use this path to find where our loader actually is.
root = idaapi.get_user_idadir()
sys.path.remove(root)

loader = imp.load_source('__loader__', os.path.join(root, 'plugins', 'minsc.py'))

## IDA's native lower-level api
if sys.platform in {'darwin'}:
    sys.meta_path.append( loader.internal_object('ida', library(idaapi.idadir("libida{:s}.dylib".format('' if idaapi.BADADDR < 0x100000000 else '64')))) )

elif sys.platform in {'linux', 'linux2'}:
    sys.meta_path.append( loader.internal_object('ida', library(idaapi.idadir("libida{:s}.so".format('' if idaapi.BADADDR < 0x100000000 else '64')))) )

elif sys.platform in {'win32'}:
    if __import__('os').path.exists(idaapi.idadir('ida.wll')):
        sys.meta_path.append( loader.internal_object('ida', library(idaapi.idadir('ida.wll'))) )
    else:
        sys.meta_path.append( loader.internal_object('ida', library(idaapi.idadir("ida{:s}.dll".format('' if idaapi.BADADDR < 0x100000000 else '64')))) )

else:
    __import__('logging').warning("{:s} : Unable to successfully load IDA's native api via ctypes. Ignoring...".format(__name__))

## private (internal) api
sys.meta_path.append( loader.internal_submodule('internal', os.path.join(root, 'base'), include='_*.py') )

## public api
sys.meta_path.append( loader.internal_path(os.path.join(root, 'base'), exclude='_*.py') )
sys.meta_path.append( loader.internal_path(os.path.join(root, 'misc')) )

# user and application api's
for subdir in ('custom', 'app'):
    sys.meta_path.append( loader.internal_submodule(subdir, os.path.join(root, subdir)) )
del(subdir)

# temporarily load the root namespace
__root__ = imp.load_source('__root__', os.path.join(root, '__root__.py'))

# save certain things within the current namespace
__original__ = {symbol : value for symbol, value in globals().items() if symbol in {'_orig_stdout', '_orig_stderr'}}

# empty out IDAPython's namespace so that we can replace it
[globals().pop(symbol) for symbol in globals().copy() if not symbol.startswith('__')]

# re-populate with a default namespace while including any symbols that needed
# preservation, and then remove both variables that contained them
globals().update({symbol : value for symbol, value in __root__.__dict__.items() if not symbol.startswith('__')})
del(__root__)

globals().update({symbol : value for symbol, value in __original__.items()})
del(__original__)

# try and execute our user's idapythonrc.py
try:
    import os
    path, filename = None, '.idapythonrc.py'

    try:
        # execute user's .pythonrc and .idapythonrc in one go
        if os.path.expanduser("~"):
            path = os.path.expanduser("~")
            exec(open(os.path.join(path, filename)).read())

    except ImportError:
        # otherwise try to figure it out without tainting the namespace
        if __import__('os').getenv('HOME', default=None) is not None:
            path = os.getenv('HOME')
            exec(open(os.path.join(path, filename)).read())
        elif __import__('os').getenv('USERPROFILE', default=None) is not None:
            path = os.getenv('USERPROFILE')
            exec(open(os.path.join(path, filename)).read())
        else:
            raise OSError("unable to determine the user's home directory.")
        pass

except IOError:
    __import__('logging').warning("No {:s} file found in the user's home directory ({!s}).".format(filename, path))

except Exception:
    __import__('logging').warning("Unexpected exception raised while trying to execute `{!s}`.".format(os.path.join(path or '~', filename)), exc_info=True)

finally:
    del(filename)
    del(path)
    del(os)

## stupid fucking idapython hax
# prevent idapython from trying to write its banner to the message window since we called it up above.
print_banner = lambda: None

# find the frame that fucks with our sys.modules, and save it for later
frame = __import__('sys')._getframe()
while frame.f_code.co_name != 'IDAPython_ExecScript':
    frame = frame.f_back

# inject our current sys.modules state into IDAPython_ExecScript's state if it's the broken version
if 'basemodules' in frame.f_locals:
    frame.f_locals['basemodules'].update(__import__('sys').modules)
del(frame)
