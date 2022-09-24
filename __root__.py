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
import segment, database, function, instruction
import structure, enumeration, ui

## some aliases for the base modules
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

def hex():
    import sys, builtins, operator
    version = sys.version_info.major
    F = operator.methodcaller('encode', 'hex') if version < 3 else operator.methodcaller('hex')
    integer_t = int, getattr(builtins, 'long', int)
    def render(item):
        return "{:x}".format(item) if isinstance(item, integer_t) else F(bytes(bytearray(item)))
    return render
hex = hex()

## other useful things that we can grab from other modules

# stuff for printing (of course)
pp, pf = pprint, pformat = [getattr(__import__('pprint'), p) for p in ['pprint', 'pformat']]
p = __import__('six').print_

# snag the custom exceptions that we use while excluding any modules
exceptions = __import__('internal').exceptions

# snag the fake utilities module to share some things with the user...
utils = __import__('internal').utils

# construct some pattern matching types
AnyRegister = utils.PatternAnyType(__import__('internal').interface.register_t)
AnyInteger = utils.PatternAnyType(__import__('six').integer_types)
AnyString = utils.PatternAnyType(__import__('six').string_types)
AnyBytes = utils.PatternAnyType(bytes)
Any = utils.PatternAny()

# some types that the user might want to compare with
architecture_t, register_t, symbol_t, bounds_t, location_t = (getattr(__import__('internal').interface, item) for item in ['architecture_t', 'register_t', 'symbol_t', 'bounds_t', 'location_t'])
ref_t, opref_t = (getattr(__import__('internal').interface, item) for item in ['ref_t', 'opref_t'])
