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
import idaapi

# grab ida's user directory and remove from it from the path since we use
# python's meta_path to locate all of our modules. we also use this path
# to find out where our loader logic is actually located.
root = idaapi.get_user_idadir()
sys.path[:] = [item for item in sys.path if os.path.realpath(item) not in {os.path.realpath(root)}]

# grab the loader, and then use it to seed python's meta_path.
if sys.version_info.major < 3 and sys.version_info.minor < 10:
    load_source = __import__('imp').load_source
else:
    def load_source(machinery, util, name, path):
        source_loader = machinery.SourceFileLoader(name, path)
        module = util.module_from_spec(util.spec_from_loader(source_loader.name, source_loader))
        source_loader.exec_module(module)
        return module
    load_source = __import__('functools').partial(load_source, __import__('importlib').machinery, __import__('importlib').util)
loader = load_source('__loader__', os.path.join(root, 'plugins', 'minsc.py'))
sys.meta_path.extend(loader.finders())
del(load_source)

# then we need to patch the version into "idaapi" so that we can
# access it when figuring out which logic we need to use.
loader.patch_version(idaapi)

# IDA 6.95 obnoxiously replaces the displayhook with their own
# version which makes it so that we can't hook it with ours.
if idaapi.__version__ >= 6.95 and hasattr(ida_idaapi, '_IDAPython_displayhook') and hasattr(ida_idaapi._IDAPython_displayhook, 'orig_displayhook'):
    sys.displayhook = ida_idaapi._IDAPython_displayhook.orig_displayhook
    del(ida_idaapi._IDAPython_displayhook)

# replace sys.displayhook with our own so that IDAPython can't
# tamper with our __repr__ implementations.
sys.displayhook = loader.DisplayHook(sys.stdout.write, sys.displayhook).displayhook

# now we can just load it into the globals() namespace, but we still
# need to preserve it as we'll need one more function after transition.
loader.load(globals(), preserve={'loader', '_orig_stdout', '_orig_stderr'})

# now we can start everything up within our namespace and then we can
# just delete the loader afterwards.
loader.startup(globals())
del(loader)

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
