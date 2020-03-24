"""
Root module

This module contains the root namespace that IDA starts up with. Any
thing defined within this module is used to replace the globals that
IDA starts up with.

This module also is responsible for assigning the default hooks in
order to trap what the user is doing to perform any extra maintenance
that needs to occur.
"""

### ida-python specific modules
import idaapi, ida

### detect which version of IDA is being used

## needed because IDA 6.95 is fucking stupid and sets the result of idaapi.get_kernel_version() to a string
def __version__():
    # api doesn't exist, go back to a crazy version.
    if not hasattr(idaapi, 'get_kernel_version'):
        return 6, 0, 6.0

    import math
    res = str(idaapi.get_kernel_version())      # force it to a str because IDA 7.0 "fixed" it
    major, minor = map(int, res.split('.', 2))
    minor = int("{:<02d}".format(minor))
    if minor > 0:
        count = math.floor(math.log(minor) / math.log(10) + 1)
        return major, minor, float(major) + minor/10**count
    return major, minor, float(major)

## inject the version info into idaapi
idaapi.__version_major__, idaapi.__version_minor__, idaapi.__version__ = __version__()

## now we can delete the function because we're done with it
del __version__

### Pre-populate the root namespace with a bunch of things that IDA requires

## IDA 6.9 requires the _idaapi module exists in the global namespace
if idaapi.__version__ <= 6.9:
    import _idaapi

## IDA 6.95 requires these couple modules to exist in the global namespace
if idaapi.__version__ >= 6.95:
    import ida_idaapi, ida_kernwin, ida_diskio

## IDA 7.4 requires that this module exists in the global namespace
if idaapi.__version__ >= 7.4:
    import sys

### customize the root namespace
import functools, operator, itertools, types
from six.moves import builtins

## context modules from ida-minsc
import segment, database, function, instruction
import structure, enumeration

## some aliases for them
import database as db
import function as func
import instruction as ins
import structure as struc
import enumeration as enum
import segment as seg

## default log setting for notifying the user
# FIXME: actually use the logging module properly instead of assuming
#        control of the root logger.
#__import__('logging').root.setLevel(__import__('logging').INFO)

## shortcuts
h, top, go, goof = database.h, func.top, database.go, database.go_offset

## other useful things that we can grab from other modules

# snag the fake utilities module to share some things with the user...
utils = __import__('internal').utils

# import all its combinators by copying them directly into locals()
locals().update({name : item for name, item in utils.__dict__.iteritems() if name in utils.__all__})

# construct some pattern matching types
AnyRegister = AnyReg = utils.PatternAnyType(__import__('internal').interface.register_t)
AnyInteger = AnyInt = utils.PatternAnyType(__import__('six').integer_types)
AnyString = AnyStr = utils.PatternAnyType(basestring)
Any = utils.PatternAny()

# ...and that's it for the utils
del(utils)

# some types that the user might want to compare with
architecture_t, register_t, symbol_t = (getattr(__import__('internal').interface, _) for _ in ('architecture_t', 'register_t', 'symbol_t'))

# other miscellaneous modules to expose to the user
import ui, tools, custom, app

### Construct a priority notification handler, and inject into IDA because it
### needs to exist for everything to initialize/deinitialize properly.

__notification__ = __import__('internal').interface.prioritynotification()
idaapi.__notification__ = __notification__

### Now we can install our hooks that initialize/uninitialize MINSC
try:
    idaapi.__notification__.add(idaapi.NW_INITIDA, __import__('hooks').make_ida_not_suck_cocks, -100)

# If installing that hook failed, then manually perform our hooks and warn the user
except NameError:
    __import__('logging').warn("Unable to add notification for idaapi.NW_INITIDA ({:d}). Setting up hooks manually...".format(idaapi.NW_INITIDA))
    __import__('hooks').make_ida_not_suck_cocks(idaapi.NW_INITIDA)

try:
    idaapi.__notification__.add(idaapi.NW_TERMIDA, __import__('hooks').make_ida_suck_cocks, -100)

# If installing the termination hook failed, then use atexit to set our hooks and warn the user
except NameError:
    __import__('logging').warn("Unable to add notification for idaapi.NW_TERMIDA ({:d}). Termination might be unstable...".format(idaapi.NW_TERMIDA))
    __import__('atexit').register(__import__('hooks').make_ida_suck_cocks, idaapi.NW_TERMIDA)
