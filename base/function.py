"""
Function module

This module exposes a number of tools that can be used on or in
a particular function. There are a couple of namespaces that can allow
one to interact with the different components that are available for
a function.

The base argument type for a number of the utilities within this module
is the ``idaapi.func_t``. This type is interchangeable with an address or
a name and either can be used to identify a function. Some of the tools
exposed in this module allow for one to modify comments, rename, or
determine the relationships between functions.

Some namespaces are provided for interacting with the different components
that IDA associates with each function. This can be used to navigate
to the different parts of a function. Some of the available namespaces
are ``type``, ``block``, ``chunk``, ``blocks``, ``chunks``, and ``frame``.
"""

import six, builtins
import functools, operator, itertools, logging

import database, instruction, structure, ui
import idaapi, internal
from internal import utils, interface, types, exceptions as E
logging = logging.getLogger(__name__)

@utils.multicase()
def has():
    '''Return if the current address is within a function.'''
    return interface.function.has(ui.current.address())
@utils.multicase(ea=types.integer)
def has(ea):
    '''Return if the address `ea` is within a function.'''
    return interface.function.has(ea)
@utils.multicase(func=idaapi.func_t)
def has(func):
    '''Return if the function `func` is a valid function.'''
    ea, _ = interface.range.bounds(fn)
    return interface.function.has(ea)
@utils.multicase(name=types.string)
@utils.string.decorate_arguments('name', 'suffix')
def has(name, *suffix):
    '''Return if the symbol with the specified `name` is within a function.'''
    res = (name,) + suffix
    string = interface.tuplename(*res)
    return True if interface.function.by_name(string) else False
@utils.multicase(frame=(idaapi.struc_t, internal.structure.structure_t))
def has(frame):
    '''Return if the structure in `frame` belongs to a function.'''
    sptr = frame if isinstance(frame, idaapi.struc_t) else frame.ptr
    return True if interface.function.by_frame(sptr) else False
within = utils.alias(has)

## searching
@utils.multicase()
def by_address():
    '''Return the function at the current address.'''
    return by_address(ui.current.address())
@utils.multicase(ea=types.integer)
def by_address(ea):
    '''Return the function containing the address `ea`.'''
    ea = interface.address.within(ea)
    res = interface.function.by_address(ea)
    if res is None:
        raise interface.function.missing(ea)
    return res
byaddress = utils.alias(by_address)

@utils.multicase(name=types.string)
@utils.string.decorate_arguments('name', 'suffix')
def by_name(name, *suffix):
    '''Return the function with the specified `name` appended with any of the elements of `suffix`.'''
    packed = (name,) + suffix
    string = interface.tuplename(*packed)
    res = interface.function.by_name(string)
    if res is None:
        raise interface.function.missing(string)
    return res
byname = utils.alias(by_name)

@utils.multicase()
def by():
    '''Return the current function.'''
    return by_address(ui.current.address())
@utils.multicase(func=idaapi.func_t)
def by(func):
    '''Return the function identified by `func`.'''
    return func
@utils.multicase(ea=types.integer)
def by(ea):
    '''Return the function at the address `ea`.'''
    return by_address(ea)
@utils.multicase(name=types.string)
@utils.string.decorate_arguments('name')
def by(name, *suffix):
    '''Return the function with the specified `name`.'''
    return by_name(name, *suffix)
@utils.multicase(frame=(idaapi.struc_t, internal.structure.structure_t))
def by(frame):
    '''Return the function that owns the specified `frame`.'''
    res = interface.function.by_frame(frame if isinstance(frame, idaapi.struc_t) else frame.ptr)
    if res is None:
        raise interface.function.missing(frame)
    return res

# FIXME: implement a matcher class for func_t

@utils.multicase()
def offset():
    '''Return the offset of the current function from the base address of the database.'''
    func = ui.current.function()
    return offset(func, 0)
@utils.multicase(func=(idaapi.func_t, types.integer))
def offset(func):
    '''Return the offset of the function `func` from the base address of the database.'''
    res = interface.function.by(func)
    ea = interface.range.start(res)
    return interface.address.offset(ea)
@utils.multicase(func=(idaapi.func_t, types.integer), offset=types.integer)
def offset(func, offset):
    '''Return the offset of the function `func` from the base address of the database and add the provided `offset` to it.'''
    res = interface.function.by(func)
    ea = interface.range.start(res)
    return interface.address.offset(ea) + offset
@utils.multicase(name=types.string)
@utils.string.decorate_arguments('name', 'suffix')
def offset(name, *suffix):
    '''Return the offset from the base address of the database for the function with the given `name`.'''
    res = (name,) + suffix
    func = interface.function.by(interface.tuplename(*res))
    ea = interface.range.start(func)
    return interface.address.offset(ea)
@utils.multicase(frame=(idaapi.struc_t, internal.structure.structure_t))
def offset(frame):
    '''Return the offset from the base address of the database for the function that owns the specified `frame`.'''
    res = interface.function.by_frame(frame if isinstance(frame, idaapi.struc_t) else frame.ptr)
    if res is None:
        raise interface.function.missing(frame)
    ea = interface.range.start(res)
    return interface.address.offset(ea)

## properties
@utils.multicase()
def comment(**repeatable):
    '''Return the comment for the current function.'''
    fn = ui.current.function()
    res = idaapi.get_func_cmt(fn, repeatable.get('repeatable', True))
    return utils.string.of(res)
@utils.multicase(func=(idaapi.func_t, types.integer))
def comment(func, **repeatable):
    """Return the comment for the function `func`.

    If the bool `repeatable` is specified, then return the repeatable comment.
    """
    fn = interface.function.by(func)
    res = idaapi.get_func_cmt(fn, repeatable.get('repeatable', True))
    return utils.string.of(res)
@utils.multicase(string=types.string)
@utils.string.decorate_arguments('string')
def comment(string, **repeatable):
    '''Set the comment for the current function to `string`.'''
    fn = ui.current.function()
    return comment(fn, string, **repeatable)
@utils.multicase(none=types.none)
def comment(none, **repeatable):
    '''Remove the comment for the current function.'''
    fn = ui.current.function()
    return comment(fn, none or '', **repeatable)
@utils.multicase(func=(idaapi.func_t, types.integer), string=types.string)
@utils.string.decorate_arguments('string')
def comment(func, string, **repeatable):
    """Set the comment for the function `func` to `string`.

    If the bool `repeatable` is specified, then modify the repeatable comment.
    """
    fn = interface.function.by(func)

    res, ok = comment(fn, **repeatable), idaapi.set_func_cmt(fn, utils.string.to(string), repeatable.get('repeatable', True))
    if not ok:
        raise E.DisassemblerError(u"{:s}.comment({:#x}, \"{:s}\"{:s}) : Unable to call `{:s}({:#x}, {!r}, {!s})`.".format(__name__, ea, utils.string.escape(string, '"'), u", {:s}".format(utils.string.kwargs(repeatable)) if repeatable else '', utils.pycompat.fullname(idaapi.set_func_cmt), ea, utils.string.to(string), repeatable.get('repeatable', True)))
    return res
@utils.multicase(func=(idaapi.func_t, types.integer), none=types.none)
def comment(func, none, **repeatable):
    """Remove the comment for the function `func`.

    If the bool `repeatable` is specified, then remove the repeatable comment.
    """
    return comment(func, none or '', **repeatable)

@utils.multicase()
def name():
    '''Return the name of the current function.'''
    return name(ui.current.address())
@utils.multicase(func=(idaapi.func_t, types.integer))
def name(func):
    '''Return the name of the function `func`.'''
    return interface.function.name(func)
@utils.multicase(frame=(idaapi.struc_t, internal.structure.structure_t))
def name(frame):
    '''Return the name of the function that is owned by the specified `frame`.'''
    res = interface.function.by_frame(frame if isinstance(frame, idaapi.struc_t) else frame.ptr)
    if res is None:
        raise interface.function.missing(frame)
    return interface.function.name(res)
@utils.multicase(none=types.none)
def name(none, **flags):
    '''Remove the custom-name from the current function.'''
    # we use ui.current.address() instead of ui.current.function()
    # in case the user might be hovering over an import table
    # function and wanting to rename that instead.
    return name(ui.current.address(), none or '', **flags)
@utils.multicase(string=types.string)
@utils.string.decorate_arguments('string', 'suffix')
def name(string, *suffix, **flags):
    '''Set the name of the current function to `string`.'''
    return name(ui.current.address(), string, *suffix, **flags)
@utils.multicase(func=(idaapi.func_t, types.integer), none=types.none)
def name(func, none, **flags):
    '''Remove the custom-name from the function `func`.'''
    return name(func, none or '', **flags)
@utils.multicase(func=(idaapi.func_t, types.integer), fullname=types.tuple)
def name(func, fullname, **flags):
    '''Set the name of the function `func` to the given packed `fullname`.'''
    return name(func, *fullname, **flags)
@utils.multicase(func=(idaapi.func_t, types.integer), string=types.string)
@utils.string.decorate_arguments('string', 'suffix')
def name(func, string, *suffix, **flags):
    """Set the name of the function `func` to `string`.

    If `flags` is specified, then use the specified value as the flags.
    If the boolean `listed` is specified, then specify whether to add the label to the Names list or not.
    """
    # figure out if address is a runtime or static function
    rt, ea = interface.addressOfRuntimeOrStatic(func)

    # combine name with its suffix
    res = (string,) + suffix
    string = interface.tuplename(*res)

    # set the default flags that we'll use based on whether the listed parameter was set.
    flag = idaapi.SN_NOWARN | (0 if flags.get('listed', idaapi.is_in_nlist(ea)) else idaapi.SN_NOLIST)

    # if it's a runtime-linked function, then it's not a public name.
    if rt:
        flag |= idaapi.SN_NON_PUBLIC

    # if it's a static function, then we need to preserve its flags.
    else:
        flag |= idaapi.SN_PUBLIC if idaapi.is_public_name(ea) else idaapi.SN_NON_PUBLIC
        flag |= idaapi.SN_WEAK if idaapi.is_weak_name(ea) else idaapi.SN_NON_WEAK

    # FIXME: mangle the name and shuffle it into the prototype if possible
    return interface.name.set(ea, string, flag, flag | idaapi.SN_NOLIST)

@utils.multicase()
def bounds():
    '''Return a tuple containing the bounds of the first chunk of the current function.'''
    try:
        fn = ui.current.function()
    except E.ItemNotFoundError:
        raise interface.function.missing(caller=[__name__, 'bounds'])
    return interface.range.bounds(fn)
@utils.multicase(func=(idaapi.func_t, types.integer))
def bounds(func):
    '''Return a tuple containing the bounds of the first chunk of the function `func`.'''
    try:
        fn = interface.function.by(func)
    except E.ItemNotFoundError:
        raise interface.function.missing(func, caller=[__name__, 'bounds'])
    return interface.range.bounds(fn)
range = utils.alias(bounds)

@utils.multicase()
def color():
    '''Return the color (RGB) of the current function.'''
    return color(ui.current.function())
@utils.multicase(func=(idaapi.func_t, types.integer))
def color(func):
    '''Return the color (RGB) of the function `func`.'''
    fn, DEFCOLOR = interface.function.by(func), 0xffffffff
    res = interface.function.color(fn)
    return None if res == DEFCOLOR else res
@utils.multicase(func=(idaapi.func_t, types.integer), none=types.none)
def color(func, none):
    '''Remove the color for the function `func`.'''
    fn, DEFCOLOR = interface.function.by(func), 0xffffffff
    res = interface.function.color(fn, DEFCOLOR)
    if res is None:
        F, ea = idaapi.update_func, interface.range.start(fn)
        raise E.DisassemblerError(u"{:s}.color({:#x}, {!s}) : Unable to clear the color of the function at {:#x} with `{:s}({:#x})`.".format(__name__, ea, none, ea, utils.pycompat.fullname(F), ea))
    return None if res == DEFCOLOR else res
@utils.multicase(func=(idaapi.func_t, types.integer), rgb=types.integer)
def color(func, rgb):
    '''Set the color (RGB) of the function `func` to `rgb`.'''
    fn, DEFCOLOR = interface.function.by(func), 0xffffffff
    res = interface.function.color(fn, rgb)
    if res is None:
        F, ea = idaapi.update_func, interface.range.start(fn)
        raise E.DisassemblerError(u"{:s}.color({:#x}, {:#x}) : Unable to set the color of the function at {:#x} with `{:s}({:#x})`.".format(__name__, ea, rgb, ea, utils.pycompat.fullname(F), ea))
    return None if res == DEFCOLOR else res
@utils.multicase(none=types.none)
def color(none):
    '''Remove the color from the current function.'''
    return color(ui.current.function(), None)

@utils.multicase()
def address():
    '''Return the address of the entrypoint for the current function.'''
    try:
        res = ui.current.function()
    except E.ItemNotFoundError:
        raise interface.function.missing(caller=[__name__, 'address'])
    return interface.range.start(res)
@utils.multicase(func=(idaapi.func_t, types.integer))
def address(func):
    '''Return the address for the entrypoint belonging to the function `func`.'''
    res = interface.function.by(func)
    return interface.range.start(res)
@utils.multicase(func=(idaapi.func_t, types.integer), offset=types.integer)
def address(func, offset):
    '''Return the address for the entrypoint belonging to the function `func` and add the provided `offset` to it.'''
    res = interface.function.by(func)
    return interface.range.start(res) + offset
@utils.multicase(name=types.string)
@utils.string.decorate_arguments('name', 'suffix')
def address(name, *suffix):
    '''Return the address for the entrypoint belonging to the function with the given `name`.'''
    res = (name,) + suffix
    res = interface.function.by(interface.tuplename(*res))
    return interface.range.start(res)
@utils.multicase(frame=(idaapi.struc_t, internal.structure.structure_t))
def address(frame):
    '''Return the address for the entrypoint of the function that owns the specified `frame`.'''
    res = interface.function.by_frame(frame if isinstance(frame, idaapi.struc_t) else frame.ptr)
    if res is None:
        raise interface.function.missing(frame)
    return interface.range.start(res)
top = addr = utils.alias(address)

@utils.multicase()
def bottom():
    '''Return the exit-points of the current function.'''
    return bottom(ui.current.function())
@utils.multicase(func=(idaapi.func_t, types.integer))
def bottom(func):
    '''Return the exit-points of the function `func`.'''
    fn = interface.function.by(func)
    fc = blocks.flowchart(fn, idaapi.FC_PREDS)
    exit_types = (
        interface.fc_block_type_t.fcb_ret,
        interface.fc_block_type_t.fcb_cndret,
        interface.fc_block_type_t.fcb_noret,
        interface.fc_block_type_t.fcb_enoret,
        interface.fc_block_type_t.fcb_error
    )
    return tuple(database.address.prev(interface.range.end(item)) for item in fc if item.type in exit_types)
@utils.multicase(frame=(idaapi.struc_t, internal.structure.structure_t))
def bottom(frame):
    '''Return the exit-points of the function that owns the specified `frame`.'''
    res = interface.function.by_frame(frame if isinstance(frame, idaapi.struc_t) else frame.ptr)
    if res is None:
        raise interface.function.missing(frame)
    return bottom(res)

@utils.multicase()
def marks():
    '''Return all the marks in the current function.'''
    return marks(ui.current.function())
@utils.multicase(func=(idaapi.func_t, types.integer))
def marks(func):
    '''Return all the marks in the function `func`.'''
    fn, res = interface.function.by(func), []
    for ea, comment in database.marks():
        try:
            if address(ea) == interface.range.start(fn):
                res.append((ea, comment))
        except E.FunctionNotFoundError:
            pass
        continue
    return res

## functions
@utils.multicase()
def new():
    '''Create a new function at the current address.'''
    return new(ui.current.address())
@utils.multicase(ea=types.integer)
def new(ea):
    '''Create a new function at the address specified by `ea`.'''
    start = interface.address.inside(ea)
    if not idaapi.add_func(start, idaapi.BADADDR):
        fullname = '.'.join([getattr(idaapi.add_func, attribute) for attribute in ['__module__', '__name__'] if hasattr(idaapi.add_func, attribute)])
        raise E.DisassemblerError(u"{:s}.new({:#x}) : Unable create a new function at the given address ({:#x}) with `{:s}`.".format(__name__, ea, start, fullname))
    ui.state.wait()
    return interface.range.bounds(interface.function.by(start))
@utils.multicase(start=types.integer, end=types.integer)
def new(start, end):
    '''Create a new function from the address `start` until `end`.'''
    bounds = ea, stop = interface.bounds_t(*interface.address.within(start, end))
    if not idaapi.add_func(ea, stop):
        fullname = '.'.join([getattr(idaapi.add_func, attribute) for attribute in ['__module__', '__name__'] if hasattr(idaapi.add_func, attribute)])
        raise E.DisassemblerError(u"{:s}.new({:#x}, {:#x}) : Unable create a new function for the given boundaries ({:s}) with `{:s}`.".format(__name__, start, end, bounds, fullname))
    ui.state.wait()
    return interface.range.bounds(interface.function.by(ea))
@utils.multicase(bounds=interface.bounds_t)
def new(bounds):
    '''Create a new function using the specified `bounds`.'''
    start, end = bounds
    return new(start, end)
make = add = utils.alias(new)

@utils.multicase()
def remove():
    '''Remove the current function from the database.'''
    return remove(ui.current.function())
@utils.multicase(func=(idaapi.func_t, types.integer))
def remove(func):
    '''Remove the function `func` from the database.'''
    fn = interface.function.by(func)
    bounds = ea, _ = interface.range.bounds(fn)
    if not idaapi.del_func(ea):
        fullname = '.'.join([getattr(idaapi.del_func, attribute) for attribute in ['__module__', '__name__'] if hasattr(idaapi.del_func, attribute)])
        raise E.DisassemblerError(u"{:s}.remove({!r}) : Unable to delete the function at {:#x} ({:s}) with `{:s}`.".format(__name__, func, interface.range.start(fn), bounds, fullname))
    return bounds
@utils.multicase(bounds=interface.bounds_t)
def remove(bounds):
    '''Remove the function specified by `bounds` from the database.'''
    ea, _ = bounds
    return remove(ea)

## chunks
class chunks(object):
    """
    This namespace is for interacting with the different chunks
    associated with a function. By default this namespace will yield
    the boundaries of each chunk associated with a function.

    Some of the ways to use this namespace are::

        > for l, r in function.chunks(): ...
        > for ea in function.chunks.iterate(ea): ...
        > for ea, delta in function.chunks.points(ea): ...

    """
    @utils.multicase()
    def __new__(cls):
        '''Return a list containing the bounds of each chunk for the current function.'''
        return cls(ui.current.function())
    @utils.multicase(func=(idaapi.func_t, types.integer))
    def __new__(cls, func):
        '''Return a list containing the bounds of each chunk for the function `func`.'''
        fn = interface.function.by(func)
        return [ interface.range.bounds(ch) for ch in interface.function.chunks(fn) ]

    @utils.multicase()
    @classmethod
    def iterate(cls):
        '''Iterate through all the instructions for each chunk in the current function.'''
        return cls.iterate(ui.current.function())
    @utils.multicase(func=(idaapi.func_t, types.integer))
    @classmethod
    def iterate(cls, func):
        '''Iterate through all the instructions for each chunk in the function `func`.'''
        for start, end in map(interface.range.bounds, interface.function.chunks(func)):
            for ea in interface.address.items(start, end):
                if interface.address.flags(ea, idaapi.MS_CLS) == idaapi.FF_CODE:
                    yield ea
                continue
            continue
        return

    @utils.multicase()
    @classmethod
    def at(cls):
        '''Return an ``idaapi.range_t`` describing the bounds of the current function chunk.'''
        return cls.at(ui.current.address())
    @utils.multicase(ea=types.integer)
    @classmethod
    def at(cls, ea):
        '''Return an ``idaapi.range_t`` describing the bounds of the function chunk at the address `ea`.'''
        fn = interface.function.by(ea)
        return cls.at(fn, ea)
    @utils.multicase(func=(idaapi.func_t, types.integer), ea=types.integer)
    @classmethod
    def at(cls, func, ea):
        '''Return an ``idaapi.range_t`` describing the bounds of the function chunk belonging to `func` at the address `ea`.'''
        fn = interface.function.by(func)
        res = interface.function.chunk(fn, ea)
        if res is None:
            raise E.AddressNotFoundError(u"{:s}.at({:#x}, {:#x}) : Unable to locate the chunk for the given address ({:#x}) in function {:#x}.".format('.'.join([__name__, cls.__name__]), interface.range.start(fn), ea, ea, interface.range.start(fn)))
        return res

    @utils.multicase()
    @classmethod
    def contains(cls):
        '''Returns True if the current function contains the current address in any of its chunks.'''
        return cls.contains(ui.current.function(), ui.current.address())
    @utils.multicase(ea=types.integer)
    @classmethod
    def contains(cls, ea):
        '''Returns True if the current function contains the address `ea` in any of its chunks.'''
        return cls.contains(ui.current.function(), ea)
    @utils.multicase(func=(idaapi.func_t, types.integer), ea=types.integer)
    @classmethod
    def contains(cls, func, ea):
        '''Returns True if the function `func` contains the address `ea` in any of its chunks.'''
        try:
            fn, ea = interface.function.by(func), interface.address.within(ea)

        # If the function is not found, or the address is out of bounds
        # then the address isn't contained in the function. Simple.
        except (E.FunctionNotFoundError, E.OutOfBoundsError):
            return False

        # If we didn't raise any exceptions, then grab all of the chunks
        # for the function that we determined.
        else:
            iterable = ( interface.range.bounds(ch) for ch in interface.function.chunks(fn) )

        # Now we can just iterate through each chunk whilst checking the bounds.
        return any(start <= ea < end for start, end in iterable)

    @utils.multicase()
    @classmethod
    def register(cls, **modifiers):
        '''Yield a reference for each operand from the current function that matches the given `modifiers`'''
        return cls.register(ui.current.function(), **modifiers)
    @utils.multicase(registers=(types.string, interface.register_t))
    @classmethod
    def register(cls, *registers, **modifiers):
        '''Yield a reference for each operand from the current function that uses any one of the given `registers`.'''
        return cls.register(ui.current.function(), *registers, **modifiers)
    @utils.multicase(func=(idaapi.func_t, types.integer))
    @classmethod
    def register(cls, func, **modifiers):
        '''Yield a reference for each operand from the function `func` that matches the given `modifiers`'''
        matches = interface.regmatch(**modifiers)
        for ea in cls.iterate(func):
            for ref in matches(ea):
                yield ref
            continue
        return
    @utils.multicase(func=(idaapi.func_t, types.integer), registers=(types.string, interface.register_t))
    @classmethod
    def register(cls, func, *registers, **modifiers):
        """Yield a reference for each operand from the function `func` that uses any one of the given `registers`.

        If the keyword `write` is true, then only return the result if it's writing to the register.
        If the keyword `read` is true, then only return the result if it's reading from the register.
        If the keyword `execute` is true, then only return the result if it's executing with the register.
        """
        matches = interface.regmatch(*registers, **modifiers)
        for ea in cls.iterate(func):
            for ref in matches(ea):
                yield ref
            continue
        return

    @utils.multicase()
    @classmethod
    def points(cls):
        '''Yield the `(address, delta)` for each stack point where the delta changes in the current function.'''
        return cls.points(ui.current.function())
    @utils.multicase(func=(idaapi.func_t, types.integer))
    @classmethod
    def points(cls, func):
        '''Yield the `(address, delta)` for each stack point where the delta changes in the function `func`.'''
        fn = interface.function.by(func)
        for ch in map(interface.range.start, interface.function.chunks(fn)):
            for ea, delta in interface.function.points(fn, ch):
                yield ea, delta
            continue
        return
    stackpoints = utils.alias(points, 'chunks')

    @utils.multicase()
    @classmethod
    def point(cls):
        '''Return the `(address, delta)` for the stack point at the current address in the current function chunk.'''
        fn, ea = ui.current.function(), ui.current.address()
        return ea, idaapi.get_spd(fn, ea)
    @utils.multicase(ea=types.integer)
    @classmethod
    def point(cls, ea):
        '''Return the `(address, delta)` for the stack point at address `ea` of the function that contains it.'''
        fn = interface.function.by(ea)
        return ea, idaapi.get_spd(fn, ea)
    @utils.multicase(func=idaapi.func_t, ea=types.integer)
    @classmethod
    def point(cls, func, ea):
        '''Return the `(address, delta)` for the stack point at address `ea` of the function `func`.'''
        fn = interface.function.by(func)
        return ea, idaapi.get_spd(fn, ea)
    @utils.multicase(ea=types.integer, delta=types.integer)
    @classmethod
    def point(cls, ea, delta, **auto):
        '''Set the stack point at address `ea` to the specified `delta`.'''
        fn = interface.function.by(ea)
        return cls.point(fn, ea, delta, **auto)
    @utils.multicase(func=(idaapi.func_t, types.integer), ea=types.integer, delta=types.integer)
    @classmethod
    def point(cls, func, ea, delta, **auto):
        """Set the stack point at address `ea` for the function `func` to the specified `delta`.

        If `auto` is set to true, then set an "auto" stack point for the function.
        Otherwise, set a user-defined stack point for the given address.
        """
        fn = interface.function.by(func)
        Fadd_user_stkpnt, Fadd_auto_stkpnt = idaapi.add_user_stkpnt, idaapi.add_auto_stkpnt2 if hasattr(idaapi, 'add_auto_stkpnt2') else idaapi.add_auto_stkpnt

        # Check the parameters for a valid "auto" keyword.
        is_auto = next((auto[k] for k in ['auto'] if k in auto), False)
        Fadd_stkpnt = functools.partial(Fadd_auto_stkpnt, fn) if is_auto else Fadd_user_stkpnt

        # If there is already a stack point at the given address, then remove it.
        current, adjustment = (F(fn, ea) for F in [idaapi.get_spd, idaapi.get_sp_delta])
        if adjustment and not idaapi.del_stkpnt(fn, ea):
            fn, description = interface.range.start(fn), "{:s}({:#x}, {:#x})".format(utils.pycompat.fullname(idaapi.del_stkpnt), interface.range.start(fn), ea)
            raise E.DisassemblerError(u"{:s}.point({:#x}, {:#x}, {:+d}{:s}) : Unable to remove existing stack point {:+#x} ({:+#x}) from the specified address ({:#x}) with `{:s}`.".format('.'.join([__name__, cls.__name__]), fn, ea, delta, ", {:s}".format(utils.string.kwargs(auto)) if auto else '', current, adjustment, ea, description))

        # Now that we've cleared the stack point, we can grab what the
        # original delta should be. We then calculate how much to adjust
        # so that we can apply our parameter as the exact stack delta.
        spd = delta - idaapi.get_spd(fn, ea)

        # Now we can add the stack point to the specified address, bailing if we couldn't.
        if not Fadd_stkpnt(ea, spd):
            fn, description = interface.range.start(fn), "{:s}({:#x}, {:#x}, {:+#x})".format(utils.pycompat.fullname(Fadd_auto_stkpnt if is_auto else Fadd_user_stkpnt), interface.range.start(fn), ea, spd)
            raise E.DisassemblerError(u"{:s}.point({:#x}, {:#x}, {:+d}{:s}) : Unable to set the stack point of the specified address ({:#x}) to {:+#x} ({:+#x}) with `{:s}`.".format('.'.join([__name__, cls.__name__]), fn, ea, delta, ", {:s}".format(utils.string.kwargs(auto)) if auto else '', ea, delta, spd, description))
        return ea, current
    @utils.multicase(func=(idaapi.func_t, types.integer), ea=types.integer, none=types.none)
    @classmethod
    def point(cls, func, ea, none):
        '''Remove the stack point at address `ea` from the function `func`.'''
        fn = interface.function.by(func)
        res = _, current = ea, idaapi.get_spd(fn, ea)

        # Attempt to delete the stack point for the specified address.
        adjustment = idaapi.get_sp_delta(fn, ea)
        if not idaapi.del_stkpnt(fn, ea):
            fn, description = interface.range.start(fn), "{:s}({:#x}, {:#x})".format(utils.pycompat.fullname(idaapi.del_stkpnt), interface.range.start(fn), ea)
            raise E.DisassemblerError(u"{:s}.point({:#x}, {:#x}, {!s}) : Unable to remove the stack point ({:+#x}) from the specified address ({:#x}) with `{:s}`.".format('.'.join([__name__, cls.__name__]), fn, ea, none, current, ea, description))
        return res
    stackpoint = utils.alias(point, 'chunks')

    @utils.multicase()
    @classmethod
    def prologue(cls):
        '''Yield the address of each instruction composing the prologue for the current function.'''
        return cls.prologue(ui.current.function())
    @utils.multicase(func=(idaapi.func_t, types.integer))
    @classmethod
    def prologue(cls, func):
        '''Yield the address of each instruction composing the prologue for the function `func`.'''
        iterable = interface.function.prologue(func)
        return (ea for ea in iterable)

    @utils.multicase()
    @classmethod
    def epilogue(cls):
        '''Yield the address of each instruction composing the epilogue for the current function.'''
        return cls.epilogue(ui.current.function())
    @utils.multicase(func=(idaapi.func_t, types.integer))
    @classmethod
    def epilogue(cls, func):
        '''Yield the address of each instruction composing the epilogue for the function `func`.'''
        iterable = interface.function.epilogue(func)
        return (ea for ea in iterable)

iterate = utils.alias(chunks.iterate, 'chunks')
contains = utils.alias(chunks.contains, 'chunks')
register = utils.alias(chunks.register, 'chunks')
point = stackpoint = utils.alias(chunks.point, 'chunks')
points = stackpoints = utils.alias(chunks.points, 'chunks')

class chunk(object):
    """
    This namespace is for interacting with a specific chunk belonging
    to a function. By default this namespace will return the bounds of
    the chunk containing the requested address.

    The functions in this namespace can be used as::

        > l, r = function.chunk(ea)
        > ea = function.chunk.top()
        > function.chunk.add(function.by(), 0x401000, 0x402000)
        > function.chunk.remove(ea)
        > for ea, delta in function.chunk.points(ea): ...
        > function.chunk.point(function.by(), ea, -0x1000)

    """
    @utils.multicase()
    def __new__(cls):
        '''Return a tuple containing the bounds of the function chunk at the current address.'''
        return cls(ui.current.address())
    @utils.multicase(ea=types.integer)
    def __new__(cls, ea):
        '''Return a tuple containing the bounds of the function chunk at the address `ea`.'''
        area = interface.function.chunk(ea, ea)
        return interface.range.bounds(area)

    @utils.multicase()
    @classmethod
    def owner(cls):
        '''Return the primary owner of the function chunk containing the current address.'''
        return cls.owner(ui.current.address())
    @utils.multicase(ea=types.integer)
    @classmethod
    def owner(cls, ea):
        '''Return the primary owner of the function chunk containing the address specified by `ea`.'''
        if within(ea):
            return next(item for item in interface.function.owners(ea))
        raise interface.function.missing(ea, caller=[__name__, cls.__name__, 'owner'])
    @utils.multicase(bounds=interface.bounds_t)
    @classmethod
    def owner(cls, bounds):
        '''Return the primary owner of the function chunk specified by `bounds`.'''
        ea, _ = bounds
        return cls.owner(ea)
    @utils.multicase(ea=types.integer, func=(idaapi.func_t, types.integer))
    @classmethod
    def owner(cls, ea, func):
        '''Set the primary owner of the chunk at `ea` to the function `func`.'''
        ea, fn = interface.address.within(ea), interface.function.by(func)
        result, ok = cls.owner(ea), idaapi.set_tail_owner(fn, ea)
        if not ok:
            fullname = '.'.join([getattr(idaapi.set_tail_owner, attribute) for attribute in ['__module__', '__name__'] if hasattr(idaapi.set_tail_owner, attribute)])
            raise E.DisassemblerError(u"{:s}.owner({#x}, {!r}) : Unable to modify the owner of the chunk at {:#x} to the given function ({:#x}) with `{:s}`.".format('.'.join([__name__, cls.__name__]), ea, func, ea, interface.range.start(fn), fullname))
        return result
    @utils.multicase(bounds=interface.bounds_t, func=(idaapi.func_t, types.integer))
    @classmethod
    def owner(cls, bounds, func):
        '''Set the primary owner of the chunk specified by `bounds` to the function `func`.'''
        ea, _ = bounds
        return cls.owner(ea, func)

    @utils.multicase()
    @classmethod
    def owners(cls):
        '''Return the owners of the current function chunk as a list.'''
        return cls.owners(ui.current.address())
    @utils.multicase(bounds=interface.bounds_t)
    @classmethod
    def owners(cls, bounds):
        '''Return the owners of the function chunk specified by `bounds` as a list.'''
        ea, _ = bounds
        return cls.owners(ea)
    @utils.multicase(ea=types.integer)
    @classmethod
    def owners(cls, ea):
        '''Return the owners which have the function chunk containing the address `ea` as a list.'''
        res, ch = idaapi.get_func(ea), idaapi.get_fchunk(ea)

        # If we're not associated with a function or we were unable to get the function chunk
        # for the provided address, then we warn the user that their result will be empty.
        if res is None or ch is None:
            message = "a function at the specified address ({:#x})".format(ea) if res is None else "a chunk at the requested address ({:#x}) for the function at {!s}".format(ea, range.bounds(res))
            logging.warning(u"{:s}.owners({:#x}) : Unable to find {:s}.".format('.'.join([__name__, cls.__name__]), ea, message))

        # Return all of the owners for the current chunk address.
        return interface.function.owners(ea)

    @utils.multicase()
    @classmethod
    def iterate(cls):
        '''Iterate through all the instructions for the function chunk containing the current address.'''
        for ea in cls.iterate(ui.current.address()):
            yield ea
        return
    @utils.multicase(ea=types.integer)
    @classmethod
    def iterate(cls, ea):
        '''Iterate through all the instructions for the function chunk containing the address ``ea``.'''
        start, end = interface.range.bounds(interface.function.chunk(ea, ea))
        for ea in interface.address.items(start, end):
            if interface.address.flags(ea, idaapi.MS_CLS) == idaapi.FF_CODE:
                yield ea
            continue
        return

    @utils.multicase()
    @classmethod
    def register(cls, **modifiers):
        '''Yield a reference for each operand from the current function chunk that matches the given `modifiers`.'''
        return cls.register(ui.current.address(), **modifiers)
    @utils.multicase(registers=(types.string, interface.register_t))
    @classmethod
    def register(cls, *registers, **modifiers):
        '''Yield a reference for each operand from the current function chunk which uses any one of the given `registers`.'''
        return cls.register(ui.current.address(), *registers, **modifiers)
    @utils.multicase(ea=types.integer)
    @classmethod
    def register(cls, ea, **modifiers):
        '''Yield a reference for each operand from the function chunk containing the address `ea` which matches the given `modifiers`.'''
        matches = interface.regmatch(**modifiers)
        for ea in cls.iterate(ea):
            for ref in matches(ea):
                yield ref
            continue
        return
    @utils.multicase(ea=types.integer, registers=(types.string, interface.register_t))
    @classmethod
    def register(cls, ea, *registers, **modifiers):
        """Yield a reference for each operand from the function chunk containing the address `ea` which any one of the given `registers`.

        If the keyword `write` is true, then only return the result if it's writing to the register.
        If the keyword `read` is true, then only return the result if it's reading from the register.
        If the keyword `execute` is true, then only return the result if it's executing with the register.
        """
        matches = interface.regmatch(*registers, **modifiers)
        for ea in cls.iterate(ea):
            for ref in matches(ea):
                yield ref
            continue
        return

    @utils.multicase()
    @classmethod
    def points(cls):
        '''Yield the `(address, delta)` for each stack point where the delta changes in the current function chunk.'''
        fn, ea = ui.current.function(), ui.current.address()
        return interface.function.points(fn, ea)
    @utils.multicase(ea=types.integer)
    @classmethod
    def points(cls, ea):
        '''Yield the `(address, delta)` for each stack point where the delta changes in the chunk containing the address `ea`.'''
        fn = interface.function.by(ea)
        return interface.function.points(fn, ea)
    @utils.multicase(func=(idaapi.func_t, types.integer), ea=types.integer)
    @classmethod
    def points(cls, func, ea):
        '''Yield the `(address, delta)` for each stack point where the delta changes in the chunk containing the address `ea` belonging to the function `func`.'''
        return interface.function.points(func, ea)
    stackpoints = utils.alias(points, 'chunk')
    stackpoint = point = utils.alias(chunks.point, 'chunks')

    @utils.multicase()
    @classmethod
    def at(cls):
        '''Return an ``idaapi.range_t`` describing the bounds of the current function chunk.'''
        return interface.function.chunk(ui.current.function(), ui.current.address())
    @utils.multicase(ea=types.integer)
    @classmethod
    def at(cls, ea):
        '''Return an ``idaapi.range_t`` describing the bounds of the function chunk at the address `ea`.'''
        fn = interface.function.by(ea)
        return interface.function.chunk(fn, ea)
    @utils.multicase(func=(idaapi.func_t, types.integer), ea=types.integer)
    @classmethod
    def at(cls, func, ea):
        '''Return an ``idaapi.range_t`` describing the bounds of the function chunk belonging to `func` at the address `ea`.'''
        return interface.function.chunk(func, ea)

    @utils.multicase()
    @classmethod
    def top(cls):
        '''Return the top address of the chunk at the current address.'''
        ea = ui.current.address()
        return interface.range.start(interface.function.chunk(ea, ea))
    @utils.multicase(ea=types.integer)
    @classmethod
    def top(cls, ea):
        '''Return the top address of the chunk at address `ea`.'''
        return interface.range.start(interface.function.chunk(ea, ea))
    @utils.multicase(ea=types.integer, address=types.integer)
    @classmethod
    def top(cls, ea, address):
        '''Change the top address of the chunk at address `ea` to the specified `address`.'''
        left = interface.range.start(interface.function.chunk(ea, ea))

        # Set the function start and return the previous top if we modified it successfully.
        result = idaapi.set_func_start(left, address)
        if result == idaapi.MOVE_FUNC_OK:
            return left

        # Otherwise we got an error code and we need to raise an exception.
        errors = {getattr(idaapi, name) : name for name in dir(idaapi) if name.startswith('MOVE_FUNC_')}
        raise E.DisassemblerError(u"{:s}.top({:#x}, {:#x}) : Unable to modify the top of the specified chunk with `{:s}({:#x}, {:#x})` due to error ({:s}).".format('.'.join([__name__, cls.__name__]), ea, address, utils.pycompat.fullname(idaapi.set_func_start), left, address, errors.get(result, "{:#x}".format(result))))

    @utils.multicase()
    @classmethod
    def bottom(cls):
        '''Return the bottom address of the chunk at the current address.'''
        ea = ui.current.address()
        return interface.range.end(interface.function.chunk(ea, ea))
    @utils.multicase(ea=types.integer)
    @classmethod
    def bottom(cls, ea):
        '''Return the bottom address of the chunk at address `ea`.'''
        return interface.range.end(interface.function.chunk(ea, ea))
    @utils.multicase(ea=types.integer, address=types.integer)
    @classmethod
    def bottom(cls, ea, address):
        '''Change the bottom address of the chunk at address `ea` to the specified `address`.'''
        left, right = interface.range.bounds(interface.function.chunk(ea, ea))
        if not idaapi.set_func_end(left, address):
            raise E.DisassemblerError(u"{:s}.bottom({:#x}, {:#x}) : Unable to modify the bottom of the specified chunk with `{:s}({:#x}, {:#x})`.".format('.'.join([__name__, cls.__name__]), ea, address, utils.pycompat.fullname(idaapi.set_func_end), left, address))
        return right

    @utils.multicase()
    @classmethod
    def address(cls):
        '''Return the top address of the function chunk containing the current address.'''
        return cls.address(ui.current.address())
    @utils.multicase(ea=types.integer)
    @classmethod
    def address(cls, ea):
        '''Return the top address of the function chunk containing the address `ea`.'''
        return interface.range.start(interface.function.chunk(ea, ea))
    @utils.multicase(ea=types.integer, offset=types.integer)
    @classmethod
    def address(cls, ea, offset):
        '''Return the address of the function chunk containing the address `ea` and add the provided `offset` to it.'''
        return interface.range.start(interface.function.chunk(ea, ea)) + offset

    @utils.multicase()
    @classmethod
    def offset(cls):
        '''Return the offset from the base of the database for the current function chunk.'''
        return cls.offset(ui.current.address(), 0)
    @utils.multicase(ea=types.integer)
    @classmethod
    def offset(cls, ea):
        '''Return the offset from the base of the database for the function chunk containing the address `ea`.'''
        return cls.offset(ea, 0)
    @utils.multicase(ea=types.integer, offset=types.integer)
    @classmethod
    def offset(cls, ea, offset):
        '''Return the offset from the base of the database for the function chunk containing the address `ea` and add the provided `offset` to it.'''
        left = interface.range.start(interface.function.chunk(ea, ea))
        return interface.address.offset(left) + offset

    @utils.multicase(start=types.integer)
    @classmethod
    def add(cls, start):
        '''Add the chunk starting at the address `start` to the current function.'''
        return cls.add(ui.current.function(), start)
    @utils.multicase(bounds=interface.bounds_t)
    @classmethod
    def add(cls, bounds):
        '''Add the chunk specified by `bounds` to the current function.'''
        return cls.add(ui.current.function(), bounds)
    @utils.multicase(func=(idaapi.func_t, types.integer), ea=types.integer)
    @classmethod
    def add(cls, func, ea):
        '''Add the chunk starting at address `ea` to the function `func`.'''
        fn = interface.function.by(func)
        start = interface.address.inside(ea)
        if not idaapi.append_func_tail(fn, start, idaapi.BADADDR):
            fullname = '.'.join([getattr(idaapi.append_func_tail, attribute) for attribute in ['__module__', '__name__'] if hasattr(idaapi.append_func_tail, attribute)])
            raise E.DisassemblerError(u"{:s}.add({!r}, {:#x}) : Unable add the chunk at the specified address ({:#x}) to the function at {:#x} with `{:s}`.".format('.'.join([__name__, cls.__name__]), func, ea, start, interface.range.start(fn), fullname))
        ui.state.wait()
        return interface.range.bounds(interface.function.chunk(start, start))
    @utils.multicase(func=(idaapi.func_t, types.integer), start=types.integer, end=types.integer)
    @classmethod
    def add(cls, func, start, end):
        '''Add the chunk from the address `start` until `end` to the function `func`.'''
        fn = interface.function.by(func)
        ea, stop = bounds = interface.bounds_t(*interface.address.within(start, end))
        if not idaapi.append_func_tail(fn, ea, stop):
            fullname = '.'.join([getattr(idaapi.append_func_tail, attribute) for attribute in ['__module__', '__name__'] if hasattr(idaapi.append_func_tail, attribute)])
            raise E.DisassemblerError(u"{:s}.add({!r}, {:#x}, {:#x}) : Unable add the specified chunk ({:s}) to the function at {:#x} with `{:s}`.".format('.'.join([__name__, cls.__name__]), func, start, end, bounds, interface.range.start(fn), fullname))
        ui.state.wait()
        return interface.range.bounds(interface.function.chunk(ea, ea))
    @utils.multicase(func=(idaapi.func_t, types.integer), bounds=interface.bounds_t)
    @classmethod
    def add(cls, func, bounds):
        '''Add the chunk specified by `bounds` to the function `func`.'''
        start, end = bounds
        return cls.add(func, start, end)

    @utils.multicase()
    @classmethod
    def remove(cls):
        '''Remove the chunk containing the current address from its function.'''
        return cls.remove(ui.current.address())
    @utils.multicase(ea=types.integer)
    @classmethod
    def remove(cls, ea):
        '''Remove the chunk at `ea` from its function.'''
        return cls.remove(ea, ea)
    @utils.multicase(bounds=interface.bounds_t)
    @classmethod
    def remove(cls, bounds):
        '''Remove the chunk specified by `bounds` from its function.'''
        ea, _ = bounds
        return cls.remove(ea, ea)
    @utils.multicase(func=(idaapi.func_t, types.integer), ea=types.integer)
    @classmethod
    def remove(cls, func, ea):
        '''Remove the chunk at `ea` from the function `func`.'''
        fn, ea = interface.function.by(func), interface.address.within(ea)
        bounds = interface.range.bounds(interface.function.chunk(fn, ea))
        if not idaapi.remove_func_tail(fn, ea):
            fullname = '.'.join([getattr(idaapi.remove_func_tail, attribute) for attribute in ['__module__', '__name__'] if hasattr(idaapi.remove_func_tail, attribute)])
            raise E.DisassemblerError(u"{:s}.remove({!r}, {:#x}) : Unable to delete the chunk ({:s}) for the function at {:#x} with `{:s}`.".format('.'.join([__name__, cls.__name__]), func, ea, bounds, interface.range.start(fn), fullname))
        return bounds
    @utils.multicase(func=(idaapi.func_t, types.integer), bounds=interface.bounds_t)
    @classmethod
    def remove(cls, func, bounds):
        '''Remove the chunk specified by `bounds` from the function `func`.'''
        ea, _ = bounds
        return cls.remove(func, ea)

    @utils.multicase()
    @classmethod
    def prologue(cls):
        '''Yield the address of each instruction composing the prologue in the current function chunk.'''
        return cls.prologue(ui.current.function())
    @utils.multicase(ea=types.integer)
    @classmethod
    def prologue(cls, ea):
        '''Yield the address of each instruction composing the prologue from the function chunk at address `ea`.'''
        fn = interface.function.by(ea)
        chunk = interface.function.chunk(fn, ea)
        iterable = interface.function.prologue(chunk)
        return (ea for ea in iterable)
    @utils.multicase(func=(idaapi.func_t, types.integer), ea=types.integer)
    @classmethod
    def prologue(cls, func, ea):
        '''Yield the address of each instruction composing the prologue from the function chunk at address `ea` belonging to `func`.'''
        chunk = interface.function.chunk(func, ea)
        iterable = interface.function.prologue(chunk)
        return (ea for ea in iterable)

    @utils.multicase()
    @classmethod
    def epilogue(cls):
        '''Yield the address for each instruction composing the epilogue in the current function chunk.'''
        return cls.epilogue(ui.current.function())
    @utils.multicase(ea=types.integer)
    @classmethod
    def epilogue(cls, ea):
        '''Yield the address for each instruction composing the epilogue from the function chunk at address `ea`.'''
        fn = interface.function.by(ea)
        chunk = interface.function.chunk(fn, ea)
        iterable = interface.function.epilogue(chunk)
        return (ea for ea in iterable)
    @utils.multicase(func=(idaapi.func_t, types.integer), ea=types.integer)
    @classmethod
    def epilogue(cls, func, ea):
        '''Yield the address for each instruction composing the epilogue from the function chunk at address `ea` belonging to `func`.'''
        chunk = interface.function.chunk(func, ea)
        iterable = interface.function.epilogue(chunk)
        return (ea for ea in iterable)

add_chunk, remove_chunk = utils.alias(chunk.add, 'chunk'), utils.alias(chunk.remove, 'chunk')

class blocks(object):
    """
    This namespace is for interacting with all of the basic blocks within
    the specified function. By default this namespace will yield the
    boundaries of each basic block defined within the function.

    This namespace provides a small number of utilities that can be
    used to extract the basic blocks of a function and convert them
    into a flow-graph such as ``idaapi.FlowChart``, or a digraph as used
    by the ``networkx`` module.

    Due to ``idaapi.FlowChart`` and networkx's digraph being used so
    often, these functions are exported globally as ``function.flowchart``
    and ``function.digraph``.

    Some examples of this namespace's usage::

        > for bb in function.blocks(calls=False): ...
        > chart = function.blocks.flowchart(ea)
        > G = function.blocks.graph()

    """
    @utils.multicase()
    def __new__(cls, **external):
        '''Return the bounds of each basic block for the current function.'''
        return cls(ui.current.function(), **external)
    @utils.multicase(func=(idaapi.func_t, types.integer))
    def __new__(cls, func, **external):
        '''Returns the bounds of each basic block for the function `func`.'''
        iterable = cls.iterate(func, **external)
        return [ interface.range.bounds(bb) for bb in iterable ]
    @utils.multicase(bounds=interface.bounds_t)
    def __new__(cls, bounds, **external):
        '''Return each basic block contained within the specified `bounds`.'''
        (left, _), (_, right) = map(interface.range.unpack, map(cls.at, bounds))
        return cls(left, right + 1, **external)
    @utils.multicase(left=types.integer, right=types.integer)
    def __new__(cls, left, right, **external):
        """Returns each basic block contained between the addresses `left` and `right`.

        If `external` is true, then include all blocks that are a branch target despite being outside the function boundaries.
        If `split` is false, then do not allow a call instruction to split a block.
        """
        fn = interface.function.by(left)

        # Define a closure that filters the basic-blocks within the given range.
        def filtered(left, right, iterable=cls.iterate(fn, **external)):
            for bb in cls.iterate(fn, **external):
                if interface.range.start(bb) >= left and interface.range.end(bb) < right:
                    yield interface.range.bounds(bb)
                continue
            return

        # Take the range we were given, and return it as a list.
        (left, _), (_, right) = map(interface.range.unpack, map(cls.at, [left, right]))
        return [ bounds for bounds in filtered(left, right) ]

    @utils.multicase()
    @classmethod
    def iterate(cls, **external):
        '''Return each ``idaapi.BasicBlock`` for the current function.'''
        return cls.iterate(ui.current.function(), **external)
    @utils.multicase(func=(idaapi.func_t, types.integer))
    @classmethod
    def iterate(cls, func, **external):
        """Returns each ``idaapi.BasicBlock`` for the function `func`.

        If `external` is true, then include all blocks that are a branch target despite being outside the function boundaries.
        If `split` is false, then do not allow a call instruction to split a block.
        """
        FC_NOEXT, FC_CALL_ENDS = getattr(idaapi, 'FC_NOEXT', 2), getattr(idaapi, 'FC_CALL_ENDS', 0x20)
        fc_flags = external.pop('flags', idaapi.FC_PREDS)
        fc_flags |= 0 if any(external.get(item, False) for item in ['external', 'externals']) else FC_NOEXT
        fc_flags |= 0 if any(not external[item] for item in ['call', 'calls', 'split'] if item in external) else FC_CALL_ENDS
        return cls.iterate(func, fc_flags)
    @utils.multicase(func=(idaapi.func_t, types.integer), flags=types.integer)
    @classmethod
    def iterate(cls, func, flags):
        '''Returns each ``idaapi.BasicBlock`` from the flowchart built with the specified `flags` (``idaapi.FC_*``) for the function `func`.'''
        for bb in interface.function.blocks(func, flags):
            yield bb
        return

    @utils.multicase()
    @classmethod
    def prologue(cls):
        '''Return a list of the basic blocks for the current function that contain any instructions that compose the prologue.'''
        return cls.prologue(ui.current.function())
    @utils.multicase(func=(idaapi.func_t, types.integer))
    @classmethod
    def prologue(cls, func):
        '''Return a list of the basic blocks for the function `func` that contain any instructions composing the prologue.'''
        result = []
        for bb in interface.function.blocks(func):
            if interface.function.prologue(bb):
                result.append(interface.range.bounds(bb))
            continue
        return result

    @utils.multicase()
    @classmethod
    def epilogue(cls):
        '''Return a list of the basic blocks for the current function contain any instructions that compose the epilogue.'''
        return cls.epilogue(ui.current.function())
    @utils.multicase(func=(idaapi.func_t, types.integer))
    @classmethod
    def epilogue(cls, func):
        '''Return a list of the basic blocks for the function `func` that contain any instructions composing the epilogue.'''
        result = []
        for bb in interface.function.blocks(func):
            if interface.function.epilogue(bb):
                result.append(interface.range.bounds(bb))
            continue
        return result

    @utils.multicase()
    @classmethod
    def walk(cls, **flags):
        '''Traverse each of the successor blocks starting from the beginning of the current function.'''
        fn = ui.current.function()
        return cls.traverse(fn, interface.range.start(fn), operator.methodcaller('succs'), **flags)
    @utils.multicase(func=(idaapi.func_t, types.integer))
    @classmethod
    def walk(cls, func, **flags):
        '''Traverse each of the successor blocks starting from the beginning of the function `func`.'''
        fn = interface.function.by(func)
        return cls.traverse(fn, interface.range.start(fn), operator.methodcaller('succs'), **flags)
    @utils.multicase(func=(idaapi.func_t, types.integer), ea=types.integer)
    @classmethod
    def walk(cls, func, ea, **flags):
        '''Traverse each of the successor blocks of the block identified by `ea` belonging to the function `func`.'''
        return cls.traverse(func, ea, operator.methodcaller('succs'), **flags)
    @utils.multicase(bb=idaapi.BasicBlock)
    @classmethod
    def walk(cls, bb):
        '''Traverse each of the successor blocks from the ``idaapi.BasicBlock`` identified by `bb`.'''
        return cls.traverse(bb, operator.methodcaller('succs'))
    @utils.multicase()
    @classmethod
    def moonwalk(cls, **flags):
        '''Traverse each of the predecessor blocks for the current function starting with the block at the current address.'''
        ea = ui.current.address()
        return cls.traverse(ea, ea, operator.methodcaller('preds'), **flags)
    @utils.multicase(ea=types.integer)
    @classmethod
    def moonwalk(cls, ea, **flags):
        '''Traverse each of the predecessor blocks for a function starting with the block at the address `ea`.'''
        return cls.traverse(ea, ea, operator.methodcaller('preds'), **flags)
    @utils.multicase(func=(idaapi.func_t, types.integer), ea=types.integer)
    @classmethod
    def moonwalk(cls, func, ea, **flags):
        '''Traverse each of the predecessor blocks from the block at address `ea` belonging to the function `func`.'''
        return cls.traverse(func, ea, operator.methodcaller('preds'), **flags)
    @utils.multicase(bb=idaapi.BasicBlock)
    @classmethod
    def moonwalk(cls, bb):
        '''Traverse each of the predecessor blocks from the ``idaapi.BasicBlock`` identified by `bb`.'''
        return cls.traverse(bb, operator.methodcaller('preds'))

    @utils.multicase()
    @classmethod
    def traverse(cls, **flags):
        '''Traverse each of the successor blocks starting from the beginning of the current function.'''
        fn = ui.current.function()
        return cls.traverse(fn, interface.range.start(fn), operator.methodcaller('succs'), **flags)
    @utils.multicase(predicate=types.callable)
    @classmethod
    def traverse(cls, predicate, **flags):
        '''Traverse the blocks from the beginning of the current function until the callable `predicate` returns no more elements.'''
        fn = ui.current.function()
        return cls.traverse(fn, interface.range.start(fn), predicate, **flags)
    @utils.multicase(func=(idaapi.func_t, types.integer), predicate=types.callable)
    @classmethod
    def traverse(cls, func, predicate, **flags):
        '''Traverse the blocks from the beginning of function `func` until the callable `predicate` returns no more elements.'''
        fn = interface.function.by(func)
        ea = interface.range.start(fn)
        return cls.traverse(fn, ea, predicate, **flags)
    @utils.multicase(func=(idaapi.func_t, types.integer), ea=types.integer, predicate=types.callable)
    @classmethod
    def traverse(cls, func, ea, predicate, **flags):
        '''Traverse the blocks of function `func` from the block given by `ea` until the callable `predicate` returns no more elements.'''
        fn = interface.function.by(func)
        bb = cls.at(fn, ea, **flags)
        return cls.traverse(bb, predicate)
    @utils.multicase(bb=idaapi.BasicBlock, predicate=types.callable)
    @classmethod
    def traverse(cls, bb, predicate):
        '''Traverse the blocks of function `func` from the ``idaapi.BasicBlock`` given by `bb` until the callable `predicate` returns no more elements.'''
        visited = {item for item in []}

        # define a closure containing the core of our functionality.
        def Fchoose(item, items, bb=bb, visited=visited):
            if item is None:
                filtered = [bounds for bounds in items if bounds not in visited]
                if len(filtered) != len(items):
                    removed = [bounds for bounds in items if bounds in visited]
                    logging.warning(u"{:s}.traverse({!s}) : Discarded {:d} already visited block{:s} ({:s}) leaving only {:d} ({:s}) to choose a default from.".format('.'.join([__name__, cls.__name__]), bb, len(removed), '' if len(removed) == 1 else 's', ', '.join(map("{:s}".format, removed)), len(filtered), ', '.join(map("{:s}".format, filtered))))
                iterable = (choice for choice in filtered[:1])
            elif isinstance(item, types.integer):
                iterable = (choice for choice in choices if choice.contains(item))
            elif item in items:
                iterable = (choice for choice in [item])
            else:
                iterable = (choice for choice in [])

            # grab our result and error out if its an integer and didn't match a block.
            result = builtins.next(iterable, None)
            if result is None and isinstance(item, types.integer):
                message = 'any of the available blocks' if len(items) > 1 else 'the only available block'
                raise E.ItemNotFoundError(u"{:s}.traverse({!s}) : The specified address ({:#x}) is not within {:s} ({:s}).".format('.'.join([__name__, cls.__name__]), bb, item, message, ', '.join(map("{:s}".format, items))))

            # otherwise, it was something else, and we couldn't match it.
            elif result is None:
                item_descr = interface.bounds_t(*item) if isinstance(item, types.tuple) else "{!s}".format(item)
                message = 'is not one of the available choices' if len(items) > 1 else 'does not match the only available block'
                raise E.ItemNotFoundError(u"{:s}.traverse({!s}) : The specified block ({:s}) {:s} ({:s}).".format('.'.join([__name__, cls.__name__]), bb, item_descr, message, ', '.join(map("{:s}".format, items))))
            return result

        # start out with the basic-block we were given, and use it for each decision.
        available = {interface.range.bounds(bb) : bb}
        choices = [interface.range.bounds(item) for item in [bb]]

        # continue while we still have choices to choose from. sort the choices so that the
        # next block will always be the first one and the rest will start from the lowest.
        while len(choices):
            selected = (yield choices if len(choices) > 1 else choices[0])
            choice = Fchoose(selected, choices)
            iterable, _ = predicate(available[choice]), visited.add(choice)
            items = [(interface.range.bounds(item), item) for item in iterable]
            available = {bounds : item for bounds, item in items}
            choices = [bounds for bounds, _ in items if choice.right == bounds.left] + [bounds for bounds, _ in sorted(items, key=operator.itemgetter(0)) if choice.right != bounds.left]
        return

    @utils.multicase()
    @classmethod
    def at(cls, **flags):
        '''Return the ``idaapi.BasicBlock`` at the current address in the current function.'''
        return cls.at(ui.current.function(), ui.current.address(), **flags)
    @utils.multicase(ea=types.integer)
    @classmethod
    def at(cls, ea, **flags):
        '''Return the ``idaapi.BasicBlock`` of address `ea` in the current function.'''
        fn = interface.function.by(ea)
        return cls.at(fn, ea, **flags)
    @utils.multicase(func=(idaapi.func_t, types.integer), ea=types.integer)
    @classmethod
    def at(cls, func, ea, **flags):
        '''Return the ``idaapi.BasicBlock`` in function `func` at address `ea`.'''
        FC_NOEXT, FC_CALL_ENDS = getattr(idaapi, 'FC_NOEXT', 2), getattr(idaapi, 'FC_CALL_ENDS', 0x20)
        fc_flags = flags.get('flags', idaapi.FC_PREDS | FC_NOEXT)
        fc_flags |= 0 if any(not flags[item] for item in ['call', 'calls', 'split'] if item in flags) else FC_CALL_ENDS
        return cls.at(func, ea, fc_flags)
    @utils.multicase(func=(idaapi.func_t, types.integer), ea=types.integer, flags=types.integer)
    @classmethod
    def at(cls, func, ea, flags):
        '''Return the ``idaapi.BasicBlock`` with the specified `flags` (``idaapi.FC_*``) for function `func` at address `ea`.'''
        fn = interface.function.by(func)
        for bb in cls.iterate(fn, flags):
            if interface.range.within(ea, bb):
                return bb
            continue
        raise E.AddressNotFoundError(u"{:s}.at({:#x}, {:#x}) : Unable to locate `{:s}` for address {:#x} in the specified function ({:#x}).".format('.'.join([__name__, cls.__name__]), interface.range.start(fn), ea, utils.pycompat.fullname(idaapi.BasicBlock), ea, interface.range.start(fn)))
    @utils.multicase(bb=idaapi.BasicBlock)
    @classmethod
    def at(cls, bb):
        '''Return the ``idaapi.BasicBlock`` matching the boundaries identifed by `bb`.'''
        bounds = interface.range.bounds(bb)

        # try and grab the idaapi.qflow_chart_t out of bb.
        fcpath = map(operator.attrgetter, ['_fc', '_q'])
        try:
            fc = functools.reduce(lambda agg, item: item(agg), fcpath, bb)

        # if we can't get ahold of the flowchart, then we need to use
        # BasicBlock's address to find the function it's a part of.
        except AttributeError:
            fn = interface.function.by(bounds.left)
            logging.warning(u"{:s}.at({!s}) : Unable to determine the flowchart from the provided `{:s}` ({:s}) for function {:#x}.".format('.'.join([__name__, cls.__name__]), bounds, utils.pycompat.fullname(idaapi.BasicBlock), bounds, interface.range.start(fn)))
            return cls.at(fn, bb)

        # now we can extract the function and its flags to regenerate the flowchart.
        fn, flags = fc.pfn, fc.flags

        # regenerate the flowchart, and generate an iterator that gives us matching
        # blocks so that we can return the first one that matches.
        iterable = (item for item in cls.iterate(fn, flags) if bounds.left == interface.range.start(item) or bounds.contains(interface.range.start(item)))
        result = builtins.next(iterable, None)
        if result is None:
            raise E.ItemNotFoundError(u"{:s}.at({!s}) : Unable to locate the `{:s}` for the given bounds ({:s}) in function {:#x}.".format('.'.join([__name__, cls.__name__]), interface.range.start(fn), bounds, utils.pycompat.fullname(idaapi.BasicBlock), bounds, interface.range.start(fn)))
        return result
    @utils.multicase(func=(idaapi.func_t, types.integer), bb=idaapi.BasicBlock)
    @classmethod
    def at(cls, func, bb):
        '''Return the ``idaapi.BasicBlock`` in function `func` identifed by `bb`.'''
        fn, bounds = interface.function.by(func), interface.range.bounds(bb)

        # now we need to extract the flags from the fc if possible.
        path = map(operator.attrgetter, ['_fc', '_q', 'flags'])
        try:
            flags = functools.reduce(lambda agg, item: item(agg), path, bb)

        # warn the user about not being able to figure it out.
        except AttributeError:
            flags = idaapi.FC_PREDS | idaapi.FC_NOEXT
            logging.warning(u"{:s}.at({:#x}, {!s}) : Unable to determine the original flags for the `{:s}` ({:s}) in function {:#x}.".format('.'.join([__name__, cls.__name__]), interface.range.start(fn), utils.pycompat.fullname(idaapi.BasicBlock), interface.range.bounds(bb), interface.range.start(fn)))

        # regenerate the flowchart, and generate an iterator that gives
        # us matching blocks. then we can return the first one and be good.
        iterable = (item for item in cls.iterate(fn, flags) if bounds.left == interface.range.start(item) or bounds.contains(interface.range.start(item)))
        result = builtins.next(iterable, None)
        if result is None:
            raise E.ItemNotFoundError(u"{:s}.at({:#x}, {!s}) : Unable to locate the `{:s}` for the given bounds ({:s}) in function {:#x}.".format('.'.join([__name__, cls.__name__]), interface.range.start(fn), bounds, utils.pycompat.fullname(idaapi.BasicBlock), bounds, interface.range.start(fn)))
        return result

    @utils.multicase()
    @classmethod
    def flowchart(cls, **flags):
        '''Return an ``idaapi.FlowChart`` object for the current function.'''
        return cls.flowchart(ui.current.function(), **flags)
    @utils.multicase(func=(idaapi.func_t, types.integer))
    @classmethod
    def flowchart(cls, func, **flags):
        '''Return an ``idaapi.FlowChart`` object for the function `func`.'''
        return cls.flowchart(func, flags.get('flags', idaapi.FC_PREDS))
    @utils.multicase(func=(idaapi.func_t, types.integer), flags=types.integer)
    @classmethod
    def flowchart(cls, func, flags):
        '''Return an ``idaapi.FlowChart`` object built with the specified `flags` for the function `func`.'''
        fn = interface.function.by(func)
        return idaapi.FlowChart(f=fn, flags=flags)
    @utils.multicase(bb=idaapi.BasicBlock)
    @classmethod
    def flowchart(cls, bb):
        '''Return an ``idaapi.FlowChart`` object for the given ``idaapi.BasicBlock``.'''
        fcpath = map(operator.attrgetter, ['_fc', '_q'])

        # try and grab the idaapi.qflow_chart_t out of bb.
        try:
            fc = functools.reduce(lambda agg, item: item(agg), fcpath, bb)

        # if we couldn't get the flowchart, then there's nothing we can do.
        except AttributeError:
            bounds = interface.range.bounds(bb)
            raise E.InvalidTypeOrValueError(u"{:s}.at({!s}) : Unable to determine the flowchart from the provided `{:s}` ({:s}).".format('.'.join([__name__, cls.__name__]), bounds, utils.pycompat.fullname(idaapi.BasicBlock), bounds))
        return fc

    @utils.multicase()
    @classmethod
    def calls(cls):
        '''Return the basic blocks from the current function that can call another function.'''
        return cls.calls(ui.current.function())
    @utils.multicase(func=(idaapi.func_t, types.integer))
    @classmethod
    def calls(cls, func):
        '''Return the basic blocks from the function `func` that can call another function.'''
        FC_CALL_ENDS, FC_NOPREDS = (getattr(idaapi, attribute, value) for attribute, value in [('FC_CALL_ENDS', 0x20), ('FC_NOPREDS', 0x40)])
        results = []
        for bb in cls.iterate(func, FC_CALL_ENDS | FC_NOPREDS):
            bounds = interface.range.bounds(bb)
            left, right = sorted(bounds)
            ea = interface.address.head(right - 1) if right > left else right
            results.append(bounds) if interface.instruction.is_call(ea) else None
        return results

    @utils.multicase()
    @classmethod
    def branches(cls):
        '''Return the basic blocks from the current function that can branch to another address.'''
        return cls.branches(ui.current.function())
    @utils.multicase(func=(idaapi.func_t, types.integer))
    @classmethod
    def branches(cls, func):
        '''Return the basic blocks from the function `func` that can branch to another address.'''
        FC_CALL_ENDS, FC_NOPREDS = (getattr(idaapi, attribute, value) for attribute, value in [('FC_CALL_ENDS', 0x20), ('FC_NOPREDS', 0x40)])
        results = []
        for bb in cls.iterate(func, FC_CALL_ENDS | FC_NOPREDS):
            bounds = interface.range.bounds(bb)
            left, right = sorted(bounds)
            ea = interface.address.head(right - 1) if right > left else right
            results.append(bounds) if interface.instruction.is_branch(ea) else None
        return results

    @utils.multicase()
    @classmethod
    @utils.string.decorate_arguments('And', 'Or', 'require', 'requires', 'required', 'include', 'includes', 'included')
    def select(cls, **boolean):
        '''Query the basic blocks of the current function for any tags specified by `boolean`'''
        return cls.select(ui.current.function(), **boolean)
    @utils.multicase(tag=types.string)
    @classmethod
    @utils.string.decorate_arguments('tag', 'And', 'Or', 'require', 'requires', 'required', 'include', 'includes', 'included')
    def select(cls, tag, *required, **boolean):
        '''Query the basic blocks of the current function for the given `tag` and any others that should be `required` or `included`.'''
        res = {tag} | {item for item in required}
        boolean['required'] = {item for item in boolean.get('required', [])} | res
        return cls.select(ui.current.function(), **boolean)
    @utils.multicase(func=(idaapi.func_t, types.integer), tag=types.string)
    @classmethod
    @utils.string.decorate_arguments('tag', 'And', 'Or', 'require', 'requires', 'required', 'include', 'includes', 'included')
    def select(cls, func, tag, *required, **boolean):
        '''Query the basic blocks of the function `func` for the given `tag` and any others that should be `required` or `included`.'''
        res = {tag} | {item for item in required}
        boolean['required'] = {item for item in boolean.get('required', [])} | res
        return cls.select(func, **boolean)
    @utils.multicase(func=(idaapi.func_t, types.integer), tags=types.unordered)
    @classmethod
    @utils.string.decorate_arguments('tags', 'And', 'Or', 'require', 'requires', 'required', 'include', 'includes', 'included')
    def select(cls, func, tags, *required, **boolean):
        '''Query the basic blocks of the function `func` for the given `tags` and any others that should be `required` or `included`.'''
        res = {item for item in tags} | {item for item in required}
        boolean['required'] = {item for item in boolean.get('required', [])} | res
        return cls.select(func, **boolean)
    @utils.multicase(func=(idaapi.func_t, types.integer))
    @classmethod
    @utils.string.decorate_arguments('And', 'Or', 'require', 'requires', 'required', 'include', 'includes', 'included')
    def select(cls, func, **boolean):
        """Query the basic blocks of the function `func` for any of the tags specified by `boolean` and yield a tuple for each matching basic block with selected tags and values.

        If `require` is given as an iterable of tag names then require that each returned block uses them.
        If `include` is given as an iterable of tag names then include the tags for each returned block if available.
        """
        boolean = {key : {item for item in value} if isinstance(value, types.unordered) else {value} for key, value in boolean.items()}

        # If we were given some parameters, then unpack both the required and/or
        # the included tags from them so that we can use them with the
        # `internal.tags.select.blocks` function.
        if boolean:
            included, required = ({item for item in itertools.chain(*(boolean.get(B, []) for B in Bs))} for Bs in [['Or', 'include', 'included', 'includes'], ['And', 'require', 'required', 'requires']])
            iterable = internal.tags.select.blocks(func, required, included)

        # If there weren't any parameters, then we can avoid using them to yield
        # all the available results.
        else:
            iterable = internal.tags.select.blocks(func)

        # Last thing to do is to convert each basic block into its range/bounds.
        return ((interface.range.bounds(bb), res) for bb, res in iterable)

    @utils.multicase()
    @classmethod
    def digraph(cls):
        '''Return a ``networkx.DiGraph`` of the function at the current address.'''
        return cls.digraph(ui.current.function())
    @utils.multicase(func=(idaapi.func_t, types.integer))
    @classmethod
    def digraph(cls, func, **flags):
        """Return a ``networkx.DiGraph`` of the function `func`.

        Requires the ``networkx`` module in order to build the graph.
        """
        fn, fcflags = interface.function.by(func), flags.get('flags', idaapi.FC_PREDS | idaapi.FC_NOEXT | getattr(idaapi, 'FC_CALL_ENDS', 0x20))
        ea = interface.range.start(fn)

        # assign some default values and create some tools to use when creating the graph
        availableChunks = [item for item in chunks(ea)]

        # create digraph
        import networkx
        attrs = internal.tags.function.get(ea)
        attrs.setdefault('__address__', ea)
        attrs.setdefault('__chunks__', availableChunks)

        # set some dot-related attributes
        attrs.setdefault('mode', 'hier')
        attrs.setdefault('splines', 'curved')
        attrs.setdefault('rankdir', 'TB')

        try:
            attrs.setdefault('__frame__', frame(fn))

        except E.MissingTypeOrAttribute:
            pass

        res, DEFCOLOR = interface.function.color(fn), 0xffffffff
        if res != DEFCOLOR:
            operator.setitem(attrs, '__color__', res)

        G = networkx.DiGraph(name=name(ea), **attrs)

        # assign some default values, and create some tools to use when adding nodes
        empty = {item for item in []}
        fVisibleTags = lambda items: {tag for tag in items if not tag.startswith('__')}

        # create a node for each block in the flowchart
        nodes_iterable, edges_iterable = itertools.tee(cls.iterate(fn, fcflags), 2)
        for B in nodes_iterable:
            bounds = block(B)

            # check if the boundary is zero-sized and handle it differently if so.
            if bounds.size:
                items = [item for item in interface.address.items(*bounds)]
                last = idaapi.prev_not_tail(bounds.right)

            # as the boundaries are defining an empty basic-block, we only need
            # to find the one address that it's actually pointing to.
            else:
                items = [item for item in {bound for bound in bounds}]
                last, = items

            # figure out all of the tags in the list of addresses (items).
            tags = [internal.tags.address.get(item) for item in items]

            # now we can continue to collect attributes to add to our graph.
            attrs = internal.tags.address.get(bounds.left)
            comment = attrs.pop('', None)
            comment and attrs.setdefault('__comment__', comment)

            attrs.setdefault('__count__', len(items))
            attrs.setdefault('__bounds__', bounds)
            attrs.setdefault('__address__', bounds.left)
            attrs.setdefault('__edge__', last)
            attrs.setdefault('__size__', getattr(bounds, 'size', bounds.right - bounds.left))

            attrs.setdefault('__entry__', bounds.left == ea or not any(B.preds()))
            attrs.setdefault('__sentinel__', interface.instruction.is_sentinel(last) or not any(B.succs()))
            attrs.setdefault('__conditional__', interface.instruction.is_conditional(last))
            attrs.setdefault('__unconditional__', any(F(last) for F in [interface.instruction.is_unconditional, interface.instruction.is_indirect]))
            attrs.setdefault('__calls__', [ea for ea in items if interface.instruction.is_call(ea)])

            attrs.setdefault('__chunk_index__', next((idx for idx, ch in enumerate(availableChunks) if ch.left <= bounds.left < ch.right), None))
            attrs.setdefault('__chunk_start__', bounds.left in {item.left for item in availableChunks})
            attrs.setdefault('__chunk_stop__', bounds.right in {item.right for item in availableChunks})

            if block.color(bounds) is not None:
                operator.setitem(attrs, '__color__', block.color(bounds))

            visibletags = [fVisibleTags(t) for t in tags]
            attrs.setdefault('__tags__', [item for item in functools.reduce(operator.or_, visibletags, empty)])

            # convert some of the attributes to dot
            operator.setitem(attrs, 'id', "{:#x}".format(bounds.left))

            if operator.contains(attrs, '__color__'):
                clr = attrs.pop('__color__')
                r, g, b = clr & 0x00ff0000 // 0x10000, clr & 0x0000ff00 // 0x100, clr & 0x000000ff // 0x1
                operator.setitem(attrs, 'color', "#{R:02x}{G:02x}{B:02x}".format(R=r, G=g, B=b))

            if attrs.get('__entry__', False):
                operator.setitem(attrs, 'rank', 'max')
                operator.setitem(attrs, 'shape', 'diamond')
                attrs.setdefault('__name__', interface.name.get(bounds.left) or interface.function.name(bounds.left))

            elif attrs.get('__sentinel__', False):
                operator.setitem(attrs, 'rank', 'min')
                operator.setitem(attrs, 'shape', 'box')

            else:
                operator.setitem(attrs, 'rank', 'same')

            operator.setitem(attrs, 'label', attrs.pop('__name__', "{:#x}<>{:#x}".format(bounds.left, bounds.right - 1)))

            # add the actual node
            G.add_node(bounds.left, **attrs)

        # for every single basic-block from the flowchart...
        for B in edges_iterable:

            # ...add an edge for its predecessors
            for Bp in B.preds():
                source, target = idaapi.prev_not_tail(interface.range.end(Bp)), interface.range.start(B)

                # FIXME: figure out some more default attributes to include
                attrs = {}
                if interface.range.end(Bp) == target:
                    operator.setitem(attrs, '__contiguous__', interface.range.end(Bp) == target)
                elif interface.instruction.is_conditional(source):
                    operator.setitem(attrs, '__conditional__', True)
                elif interface.instruction.is_unconditional(source) or interface.instruction.is_indirect(source):
                    operator.setitem(attrs, '__unconditional__', True)
                else:
                    operator.setitem(attrs, '__branch__', interface.instruction.is_branch(source))

                # add the dot attributes for the edge
                operator.setitem(attrs, 'dir', 'forward')

                if any(attrs.get(item, False) for item in ['__branch__', '__conditional__', '__unconditional__']):
                    attrs['label'] = instruction.mnem(source)

                # add the edge to the predecessor
                G.add_edge(interface.range.start(Bp), target, **attrs)

            # ...add an edge for its successors
            for Bs in B.succs():
                source, target = idaapi.prev_not_tail(interface.range.end(B)), interface.range.start(Bs)

                # FIXME: figure out some more default attributes to include
                attrs = {}
                if interface.range.end(B) == target:
                    operator.setitem(attrs, '__contiguous__', interface.range.end(B) == target)
                elif interface.instruction.is_conditional(source):
                    operator.setitem(attrs, '__conditional__', True)
                elif interface.instruction.is_unconditional(source) or interface.instruction.is_indirect(source):
                    operator.setitem(attrs, '__unconditional__', True)
                else:
                    operator.setitem(attrs, '__branch__', interface.instruction.is_branch(source))

                # add the dot attributes for the edge
                operator.setitem(attrs, 'dir', 'forward')

                if any(attrs.get(item, False) for item in ['__branch__', '__conditional__', '__unconditional__']):
                    attrs['label'] = instruction.mnem(source)

                # add the edge to the successor
                G.add_edge(interface.range.start(B), target, **attrs)
            continue
        return G
    graph = utils.alias(digraph, 'blocks')

    @utils.multicase(start=types.integer, exits=(types.integer, types.unordered))
    @classmethod
    def subgraph(cls, start, exits):
        '''Return a ``networkx.DiGraph`` subgraph of the current function from address `start` and terminating at any address in `exits`.'''
        return cls.subgraph(ui.current.function(), start, exits)
    @utils.multicase(func=(idaapi.func_t, types.integer), start=types.integer, exits=(types.integer, types.unordered))
    @classmethod
    def subgraph(cls, func, start, exits):
        """Return a ``networkx.DiGraph`` subgraph of the function `func` from address `start` and terminating at any address in `exits`.

        Requires the ``networkx`` module in order to build the graph.
        """
        g, exits = cls.digraph(func), {item for item in exits} if hasattr(exits, '__iter__') else {exits}
        start_block = block(start).left
        exit_blocks = { item.left for item in map(block, exits) }

        # Generate the subgraph using nodes that are within the path the user specified.
        import networkx
        nodes = {ea for ea in g.nodes if networkx.has_path(g, start_block, ea) and any(networkx.has_path(g, ea, item) for item in exit_blocks)}
        G = g.subgraph(nodes)

        # Update the node attributes so that the entry and exits can still be used.
        [ operator.setitem(G.nodes[item], '__entry__', True) for item in [start_block] ]
        [ operator.setitem(G.nodes[item], '__sentinel__', not G.succ[item]) for item in G ]
        return G

    # XXX: Implement .register for filtering blocks
    # XXX: Implement .search for filtering blocks
flowchart = utils.alias(blocks.flowchart, 'blocks')
digraph = graph = utils.alias(blocks.digraph, 'blocks')

class block(object):
    """
    This namespace is for interacting with a single basic block
    belonging to a function. By default the bounds of the selected
    basic block will be returned. This bounds or an address within
    these bounds can then be used in other functions within this
    namespace.

    Some examples of this functionality can be::

        > B = function.block(ea)
        > bid = function.block.id()
        > c = function.block.color(ea, rgb)
        > print( function.block.before(ea) )
        > for ea in function.block.iterate(): print( database.disasm(ea) )
        > for ea, op, st in function.block.register('eax', read=1): ...
        > print( function.block.read().encode('hex') )
        > print( function.block.disasm(ea) )

    """
    @utils.multicase()
    @classmethod
    def at(cls, **flags):
        '''Return the ``idaapi.BasicBlock`` of the current address in the current function.'''
        return cls.at(ui.current.function(), ui.current.address(), **flags)
    @utils.multicase(ea=types.integer)
    @classmethod
    def at(cls, ea, **flags):
        '''Return the ``idaapi.BasicBlock`` of address `ea` in the current function.'''
        fn = interface.function.by(ea)
        return cls.at(fn, ea, **flags)
    @utils.multicase(func=(idaapi.func_t, types.integer), ea=types.integer)
    @classmethod
    def at(cls, func, ea, **flags):
        '''Return the ``idaapi.BasicBlock`` of address `ea` in the function `func`.'''
        return blocks.at(func, ea, **flags)
    @utils.multicase(bb=idaapi.BasicBlock)
    @classmethod
    def at(cls, bb):
        '''Return the ``idaapi.BasicBlock`` of the basic block `bb`.'''
        return bb
    @utils.multicase(bounds=interface.bounds_t)
    @classmethod
    def at(cls, bounds, **flags):
        '''Return the ``idaapi.BasicBlock`` identified by `bounds`.'''
        left, _ = bounds
        return cls.at(left, **flags)

    @utils.multicase()
    @classmethod
    def id(cls):
        '''Return the block id of the current address in the current function.'''
        return cls.at(ui.current.function(), ui.current.address()).id
    @utils.multicase(ea=types.integer)
    @classmethod
    def id(cls, ea):
        '''Return the block id of address `ea` in the current function.'''
        return cls.at(ea).id
    @utils.multicase(func=(idaapi.func_t, types.integer), ea=types.integer)
    @classmethod
    def id(cls, func, ea):
        '''Return the block id of address `ea` in the function `func`.'''
        return cls.at(func, ea).id
    @utils.multicase(bb=idaapi.BasicBlock)
    @classmethod
    def id(cls, bb):
        '''Return the block id of the basic block `bb`.'''
        return bb.id
    @utils.multicase(bounds=interface.bounds_t)
    @classmethod
    def id(cls, bounds):
        '''Return the block id of the basic block identified by `bounds`.'''
        return cls.at(bounds).id

    @utils.multicase()
    def __new__(cls, **flags):
        '''Returns the boundaries of the current basic block.'''
        return cls(ui.current.function(), ui.current.address(), **flags)
    @utils.multicase(ea=types.integer)
    def __new__(cls, ea, **flags):
        '''Returns the boundaries of the basic block at address `ea`.'''
        return cls(interface.function.by(ea), ea, **flags)
    @utils.multicase(func=(idaapi.func_t, types.integer), ea=types.integer)
    def __new__(cls, func, ea, **flags):
        '''Returns the boundaries of the basic block at address `ea` in function `func`.'''
        res = blocks.at(func, ea, **flags)
        return interface.range.bounds(res)
    @utils.multicase(func=(idaapi.func_t, types.integer), ea=types.integer, flags=types.integer)
    def __new__(cls, func, ea, flags):
        '''Returns the boundaries of the basic block with the specified `flags` (``idaapi.FC_*``) at address `ea` in function `func`.'''
        res = blocks.at(func, ea, flags)
        return interface.range.bounds(res)
    @utils.multicase(bb=idaapi.BasicBlock)
    def __new__(cls, bb):
        '''Returns the boundaries of the basic block `bb`.'''
        return interface.range.bounds(bb)
    @utils.multicase(bounds=interface.bounds_t)
    def __new__(cls, bounds, **flags):
        '''Return the boundaries of the basic block identified by `bounds`.'''
        left, _ = bounds
        return cls(left, **flags)

    @utils.multicase(ea=types.integer)
    @classmethod
    def contains(cls, ea):
        '''Return whether the address `ea` is within the current basic block.'''
        left, right = cls()
        return left <= ea < right
    @utils.multicase(address=types.integer, ea=types.integer)
    @classmethod
    def contains(cls, address, ea):
        '''Return whether the address `ea` is within the basic block at the specified `address`.'''
        left, right = cls(address)
        return left <= ea < right
    @utils.multicase(func=(idaapi.func_t, types.integer), address=types.integer, ea=types.integer)
    @classmethod
    def contains(cls, func, address, ea):
        '''Return whether the address `ea` is within the basic block for the function `func` at the specified `address`.'''
        left, right = cls(func, address)
        return left <= ea < right
    @utils.multicase(bb=idaapi.BasicBlock, ea=types.integer)
    @classmethod
    def contains(cls, bb, ea):
        '''Return whether the address `ea` is within the basic block `bb`.'''
        left, right = cls(bb)
        return left <= ea < right
    @utils.multicase(bounds=interface.bounds_t, ea=types.integer)
    @classmethod
    def contains(cls, bounds, ea):
        '''Return whether the address `ea` is within the basic block identified by `bounds`.'''
        left, right = cls(bounds)
        return left <= ea < right

    @utils.multicase()
    @classmethod
    def top(cls):
        '''Return the top address of the basic block at the current address.'''
        left, _ = cls()
        return left
    @utils.multicase(ea=types.integer)
    @classmethod
    def top(cls, ea):
        '''Return the top address of the basic block at address `ea`.'''
        left, _ = cls(ea)
        return left
    @utils.multicase(bb=idaapi.BasicBlock)
    @classmethod
    def top(cls, bb):
        '''Return the top address of the basic block `bb`.'''
        left, _ = cls(bb)
        return left
    @utils.multicase(bounds=interface.bounds_t)
    @classmethod
    def top(cls, bounds):
        '''Return the top address of the basic block identified by `bounds`.'''
        left, _ = cls(bounds)
        return left
    address = addr = utils.alias(top, 'block')

    @utils.multicase()
    @classmethod
    def bottom(cls):
        '''Return the bottom address of the basic block at the current address.'''
        _, right = cls()
        return right
    @utils.multicase(ea=types.integer)
    @classmethod
    def bottom(cls, ea):
        '''Return the bottom address of the basic block at address `ea`.'''
        _, right = cls(ea)
        return right
    @utils.multicase(bb=idaapi.BasicBlock)
    @classmethod
    def bottom(cls, bb):
        '''Return the bottom address of the basic block `bb`.'''
        _, right = cls(bb)
        return right
    @utils.multicase(bounds=interface.bounds_t)
    @classmethod
    def bottom(cls, bounds):
        '''Return the bottom address of the basic block identified by `bounds`.'''
        _, right = cls(bounds)
        return right

    @utils.multicase()
    @classmethod
    def address(cls):
        '''Return the top address for the basic block containing the current address.'''
        return cls.address(ui.current.address(), 0)
    @utils.multicase(ea=types.integer)
    @classmethod
    def address(cls, ea):
        '''Return the top address for the basic block containing the address `ea`.'''
        return cls.address(ea, 0)
    @utils.multicase(ea=types.integer, offset=types.integer)
    @classmethod
    def address(cls, ea, offset):
        '''Return the top address for the basic block containing the address `ea` and add the provided `offset` to it.'''
        left, _ = cls(ea)
        return left + offset

    @utils.multicase()
    @classmethod
    def offset(cls):
        '''Return the offset from the base of the database for the basic block at the current address.'''
        return cls.offset(ui.current.address(), 0)
    @utils.multicase(ea=types.integer)
    @classmethod
    def offset(cls, ea):
        '''Return the offset from the base of the database for the basic block at the address `ea`.'''
        return cls.offset(ea, 0)
    @utils.multicase(ea=types.integer, offset=types.integer)
    @classmethod
    def offset(cls, ea, offset):
        '''Return the offset from the base of the database for the basic block at address `ea` and add the provided `offset` to it.'''
        left, _ = cls(ea)
        return interface.address.offset(left) + offset

    @utils.multicase()
    @classmethod
    def color(cls):
        '''Returns the color of the basic block at the current address.'''
        return cls.color(ui.current.address())
    @utils.multicase(none=types.none)
    @classmethod
    def color(cls, none):
        '''Removes the color of the basic block at the current address.'''
        return cls.color(ui.current.address(), None)
    @utils.multicase(ea=types.integer)
    @classmethod
    def color(cls, ea, **frame):
        '''Returns the color of the basic block at the address `ea`.'''
        bb, DEFCOLOR = blocks.at(ea), 0xffffffff
        res = interface.function.blockcolor(bb, **frame)
        return None if res == DEFCOLOR else res
    @utils.multicase(bb=idaapi.BasicBlock)
    @classmethod
    def color(cls, bb, **frame):
        '''Returns the color of the basic block `bb`.'''
        res, DEFCOLOR = interface.function.blockcolor(bb, **frame), 0xffffffff
        return None if res == DEFCOLOR else res
    @utils.multicase(bounds=interface.bounds_t)
    @classmethod
    def color(cls, bounds):
        '''Returns the color of the basic block identified by `bounds`.'''
        bb = cls.at(bounds)
        return cls.color(bb)
    @utils.multicase(ea=types.integer, none=types.none)
    @classmethod
    def color(cls, ea, none, **frame):
        '''Removes the color of the basic block at the address `ea`.'''
        bb, DEFCOLOR = blocks.at(ea), 0xffffffff
        res = interface.function.blockcolor(bb, DEFCOLOR, **frame)
        for ea in block.iterate(ea):
            interface.address.color(ea, DEFCOLOR)
        return None if res == DEFCOLOR else res
    @utils.multicase(bounds=interface.bounds_t, none=types.none)
    @classmethod
    def color(cls, bounds, none):
        '''Removes the color of the basic block identified by `bounds`.'''
        bb = cls.at(bounds)
        return cls.color(bb, None)
    @utils.multicase(bb=idaapi.BasicBlock, none=types.none)
    @classmethod
    def color(cls, bb, none, **frame):
        '''Removes the color of the basic block `bb`.'''
        DEFCOLOR = 0xffffffff
        res = interface.function.blockcolor(bb, DEFCOLOR, **frame)
        for ea in block.iterate(bb):
            interface.address.color(ea, DEFCOLOR)
        return None if res == DEFCOLOR else res
    @utils.multicase(ea=types.integer, rgb=types.integer)
    @classmethod
    def color(cls, ea, rgb, **frame):
        """Sets the color of the basic block at the address `ea` to `rgb`.

        If the color `frame` is specified, set the frame to the specified color or both the frame and background if true.
        """
        bb, DEFCOLOR = blocks.at(ea), 0xffffffff
        res = interface.function.blockcolor(bb, rgb, **frame)
        for ea in block.iterate(bb):
            interface.address.color(ea, rgb)
        return None if res == DEFCOLOR else res
    @utils.multicase(bb=idaapi.BasicBlock, rgb=types.integer)
    @classmethod
    def color(cls, bb, rgb, **frame):
        '''Sets the color of the basic block `bb` to `rgb`.'''
        res, DEFCOLOR = interface.function.blockcolor(bb, rgb, **frame), 0xffffffff
        for ea in block.iterate(bb):
            interface.address.color(ea, rgb)
        return None if res == DEFCOLOR else res
    @utils.multicase(bounds=interface.bounds_t, rgb=types.integer)
    @classmethod
    def color(cls, bounds, rgb, **frame):
        '''Sets the color of the basic block identifed by `bounds` to `rgb`.'''
        bb = cls.at(bounds)
        return cls.color(bb, rgb, **frame)

    @utils.multicase()
    @classmethod
    def before(cls):
        '''Return the address for each instruction that will be executed before the current basic block.'''
        return cls.before(ui.current.address())
    @utils.multicase(ea=types.integer)
    @classmethod
    def before(cls, ea):
        '''Return the address for each instruction that will be executed before the basic block at address `ea`.'''
        res = blocks.at(ea)
        return cls.before(res)
    @utils.multicase(bounds=interface.bounds_t)
    @classmethod
    def before(cls, bounds):
        '''Return the address for each instruction that will be executed before the basic block identified by `bounds`.'''
        bb = cls.at(bounds)
        return cls.before(bb)
    @utils.multicase(bb=idaapi.BasicBlock)
    @classmethod
    def before(cls, bb):
        '''Return the address for each instruction that will be executed before the basic block `bb`.'''
        return [ idaapi.prev_not_tail(interface.range.end(bb)) for bb in bb.preds() ]
    predecessors = preds = utils.alias(before, 'block')

    @utils.multicase()
    @classmethod
    def after(cls):
        '''Return the address for each instruction that will follow the execution of the current basic block.'''
        return cls.after(ui.current.address())
    @utils.multicase(ea=types.integer)
    @classmethod
    def after(cls, ea):
        '''Return the address for each instruction that will follow the execution of the basic block at address `ea`.'''
        bb = cls.at(ea)
        return cls.after(bb)
    @utils.multicase(bounds=interface.bounds_t)
    @classmethod
    def after(cls, bounds):
        '''Return the address for each instruction that will follow the execution of the basic block identified by `bounds`.'''
        bb = cls.at(bounds)
        return cls.after(bb)
    @utils.multicase(bb=idaapi.BasicBlock)
    @classmethod
    def after(cls, bb):
        '''Return the address for each instruction that will follow the execution of basic block `bb`.'''
        return [interface.range.start(bb) for bb in bb.succs()]
    successors = succs = utils.alias(after, 'block')

    @utils.multicase()
    @classmethod
    def previous(cls):
        '''Return the basic block that is previous (contiguously) of the current basic block.'''
        left, right = cls()
        return cls(left - 1)
    @utils.multicase(ea=types.integer)
    @classmethod
    def previous(cls, ea):
        '''Return the basic block that is previous (contiguously) of the basic block at address `ea`.'''
        left, right = cls(ea)
        return cls(left - 1)
    @utils.multicase(bounds=interface.bounds_t)
    @classmethod
    def previous(cls, bounds):
        '''Return the basic block that is previous (contiguously) of the basic block identified by `bounds`.'''
        left, right = cls(bounds)
        return cls(left - 1)
    @utils.multicase(bb=idaapi.BasicBlock)
    @classmethod
    def previous(cls, bb):
        '''Return the basic block that is previous (contiguously) of the basic block `bb`.'''
        left, right = cls(bb)
        return cls(left - 1)
    prev = utils.alias(previous, 'block')

    @utils.multicase()
    @classmethod
    def next(cls):
        '''Return the basic block that is after (contiguously) the current basic block.'''
        left, right = cls()
        return cls(right)
    @utils.multicase(ea=types.integer)
    @classmethod
    def next(cls, ea):
        '''Return the basic block that is after (contiguously) the basic block at address `ea`.'''
        left, right = cls(ea)
        return cls(right)
    @utils.multicase(bounds=interface.bounds_t)
    @classmethod
    def next(cls, bounds):
        '''Return the basic block that is after (contiguously) the basic block identified by `bounds`.'''
        left, right = cls(bounds)
        return cls.at(right)
    @utils.multicase(bb=idaapi.BasicBlock)
    @classmethod
    def next(cls, bb):
        '''Return the basic block that is after (contiguously) the basic block `bb`.'''
        left, right = cls(bb)
        return cls.at(right)

    @utils.multicase()
    @classmethod
    def iterate(cls):
        '''Yield all the addresses in the current basic block.'''
        return cls.iterate(ui.current.address())
    @utils.multicase(ea=types.integer)
    @classmethod
    def iterate(cls, ea):
        '''Yield all the addresses in the basic block at address `ea`.'''
        left, right = cls(ea)
        return interface.address.items(left, right)
    @utils.multicase(bounds=interface.bounds_t)
    @classmethod
    def iterate(cls, bounds):
        '''Yield all the addresses in the basic block identified by `bounds`.'''
        return interface.address.items(*bounds)
    @utils.multicase(bb=idaapi.BasicBlock)
    @classmethod
    def iterate(cls, bb):
        '''Yield all the addresses in the basic block `bb`.'''
        left, right = interface.range.unpack(bb)
        return interface.address.items(left, right)

    @utils.multicase()
    @classmethod
    def prologue(cls):
        '''Return a list of the addresses from the current basic block that compose the prologue.'''
        return cls.prologue(ui.current.address())
    @utils.multicase(ea=types.integer)
    @classmethod
    def prologue(cls, ea):
        '''Return a list of the addresses from the basic block at address `ea` that compose the prologue.'''
        fn = interface.function.by(ea)
        bb = interface.function.block(fn, ea)
        return interface.function.prologue(bb)
    @utils.multicase(bounds=(interface.bounds_t, idaapi.BasicBlock, idaapi.area_t if idaapi.__version__ < 7.0 else idaapi.range_t))
    @classmethod
    def prologue(cls, bounds):
        '''Return a list of the addresses from the basic block identified by `bounds` that compose the prologue.'''
        return interface.function.prologue(bounds)

    @utils.multicase()
    @classmethod
    def epilogue(cls):
        '''Return a list of the addresses from the current basic block that compose the epilogue.'''
        return cls.epilogue(ui.current.address())
    @utils.multicase(ea=types.integer)
    @classmethod
    def epilogue(cls, ea):
        '''Return a list of the addresses from the basic block at address `ea` that compose the epilogue.'''
        fn = interface.function.by(ea)
        bb = interface.function.block(fn, ea)
        return interface.function.epilogue(bb)
    @utils.multicase(bounds=(interface.bounds_t, idaapi.BasicBlock, idaapi.area_t if idaapi.__version__ < 7.0 else idaapi.range_t))
    @classmethod
    def epilogue(cls, bounds):
        '''Return a list of the addresses from the basic block identified by `bounds` that compose the epilogue.'''
        return interface.function.epilogue(bounds)

    # current block
    @utils.multicase()
    @classmethod
    def tag(cls):
        '''Returns all the tags defined for the current basic block.'''
        return cls.tag(ui.current.address())
    @utils.multicase(key=types.string)
    @classmethod
    @utils.string.decorate_arguments('key')
    def tag(cls, key):
        '''Returns the value of the tag identified by `key` for the current basic block.'''
        return cls.tag(ui.current.address(), key)
    @utils.multicase(key=types.string)
    @classmethod
    @utils.string.decorate_arguments('key')
    def tag(cls, key, value):
        '''Sets the value for the tag `key` to `value` for the current basic block.'''
        return cls.tag(ui.current.address(), key, value)
    @utils.multicase(key=types.string, none=types.none)
    @classmethod
    @utils.string.decorate_arguments('key')
    def tag(cls, key, none):
        '''Removes the tag identified by `key` for the current basic block.'''
        return cls.tag(ui.current.address(), key, none)

    # address or bounds of block
    @utils.multicase(ea=(types.integer, interface.bounds_t))
    @classmethod
    def tag(cls, ea):
        '''Returns all the tags defined for the basic block at `ea`.'''
        bb = cls.at(ea)
        return cls.tag(bb)
    @utils.multicase(ea=(types.integer, interface.bounds_t), key=types.string)
    @classmethod
    @utils.string.decorate_arguments('key')
    def tag(cls, ea, key):
        '''Returns the value of the tag identified by `key` for the basic block at `ea`.'''
        bb = cls.at(ea)
        return cls.tag(bb, key)
    @utils.multicase(ea=(types.integer, interface.bounds_t), key=types.string)
    @classmethod
    @utils.string.decorate_arguments('key', 'value')
    def tag(cls, ea, key, value):
        '''Sets the value for the tag `key` to `value` for the basic block at `ea`.'''
        bb = cls.at(ea)
        return cls.tag(bb, key, value)
    @utils.multicase(ea=(types.integer, interface.bounds_t), key=types.string, none=types.none)
    @classmethod
    @utils.string.decorate_arguments('key')
    def tag(cls, ea, key, none):
        '''Removes the tag identified by `key` for the basic block at `ea`.'''
        bb = cls.at(ea)
        return cls.tag(bb, key, none)

    # actual basic block
    @utils.multicase(bb=idaapi.BasicBlock)
    @classmethod
    @utils.string.decorate_arguments('key', 'value')
    def tag(cls, bb):
        '''Returns all the tags defined for the ``idaapi.BasicBlock`` given in `bb`.'''
        return internal.tags.block.get(bb)
    @utils.multicase(bb=idaapi.BasicBlock, key=types.string)
    @classmethod
    @utils.string.decorate_arguments('key', 'value')
    def tag(cls, bb, key):
        '''Returns the value of the tag identified by `key` from the ``idaapi.BasicBlock`` given in `bb`.'''
        res = internal.tags.block.get(bb)
        if key in res:
            return res[key]
        bounds = interface.range.bounds(bb)
        raise E.MissingTagError(u"{:s}.tag({!s}, {!r}) : Unable to read the specified tag (\"{:s}\") from the basic block ({:s}).".format(__name__, bounds, key, utils.string.escape(key, '"'), bounds))
    @utils.multicase(bb=idaapi.BasicBlock, key=types.string)
    @classmethod
    @utils.string.decorate_arguments('key', 'value')
    def tag(cls, bb, key, value):
        '''Sets the value for the tag `key` to `value` in the ``idaapi.BasicBlock`` given by `bb`.'''
        return internal.tags.block.set(bb, key, value)
    @utils.multicase(bb=idaapi.BasicBlock, key=types.string, none=types.none)
    @classmethod
    @utils.string.decorate_arguments('key')
    def tag(cls, bb, key, none):
        '''Removes the tag identified by `key` from the ``idaapi.BasicBlock`` given by `bb`.'''
        return internal.tags.block.remove(bb, key, none)

    @utils.multicase()
    @classmethod
    def register(cls, **modifiers):
        '''Yield a reference for each operand from the current block that matches the given `modifiers`.'''
        return cls.register(ui.current.address(), **modifiers)
    @utils.multicase(registers=(types.string, interface.register_t))
    @classmethod
    def register(cls, *registers, **modifiers):
        '''Yield a reference for each operand from the current block that uses any one of the given `registers`.'''
        return cls.register(ui.current.address(), *registers, **modifiers)
    @utils.multicase(ea=types.integer)
    @classmethod
    def register(cls, ea, **modifiers):
        '''Yield a reference for each operand from the block containing `ea` that matches the given `modifiers`.'''
        bb = cls.at(ea, **modifiers)
        return cls.register(bb, **modifiers)
    @utils.multicase(ea=types.integer, registers=(types.string, interface.register_t))
    @classmethod
    def register(cls, ea, *registers, **modifiers):
        '''Yield a reference for each operand from the block containing `ea` that uses any one of the given `registers`.'''
        bb = cls.at(ea, **modifiers)
        return cls.register(bb, *registers, **modifiers)
    @utils.multicase(block=(interface.bounds_t, idaapi.BasicBlock))
    @classmethod
    def register(cls, block, **modifiers):
        '''Yield a reference for each operand from the specified `block` that matches the given `modifiers`.'''
        matches = interface.regmatch(**modifiers)
        left, right = interface.range.unpack(block) if isinstance(block, idaapi.BasicBlock) else block
        for ea in interface.address.items(left, right):
            for ref in matches(ea):
                yield ref
            continue
        return
    @utils.multicase(block=(interface.bounds_t, idaapi.BasicBlock), registers=(types.string, interface.register_t))
    @classmethod
    def register(cls, block, *registers, **modifiers):
        """Yield a reference for each operand from the specified `block` that uses any one of the given `registers`.

        If the keyword `write` is true, then only return the result if it's writing to the register.
        If the keyword `read` is true, then only return the result if it's reading from the register.
        If the keyword `execute` is true, then only return the result if it's executing with the register.
        """
        matches = interface.regmatch(*registers, **modifiers)
        left, right = interface.range.unpack(block) if isinstance(block, idaapi.BasicBlock) else block
        for ea in interface.address.items(left, right):
            for ref in matches(ea):
                yield ref
            continue
        return

    @utils.multicase()
    @classmethod
    def read(cls):
        '''Return all the bytes contained in the current basic block.'''
        return cls.read(ui.current.address())
    @utils.multicase(ea=types.integer)
    @classmethod
    def read(cls, ea):
        '''Return all the bytes contained in the basic block at address `ea`.'''
        bb = cls.at(ea)
        return cls.read(bb)
    @utils.multicase(bounds=interface.bounds_t)
    @classmethod
    def read(cls, bounds):
        '''Return all the bytes contained in the basic block identified by `bounds`.'''
        bb = cls.at(bounds)
        return cls.read(bb)
    @utils.multicase(bb=idaapi.BasicBlock)
    @classmethod
    def read(cls, bb):
        '''Return all the bytes contained in the basic block `bb`.'''
        bounds = ea, _ = interface.range.bounds(bb)
        return interface.address.read(ea, bounds.size)

    @utils.multicase()
    @classmethod
    def disassemble(cls, **options):
        '''Returns the disassembly of the basic block at the current address.'''
        return cls.disassemble(ui.current.address(), **options)
    @utils.multicase(ea=types.integer)
    @classmethod
    def disassemble(cls, ea, **options):
        '''Returns the disassembly of the basic block at the address `ea`.'''
        F = functools.partial(database.disassemble, **options)
        return '\n'.join(map(F, cls.iterate(ea)))
    @utils.multicase(bounds=interface.bounds_t)
    @classmethod
    def disassemble(cls, bounds, **options):
        '''Returns the disassembly of the basic block identified by `bounds`.'''
        bb = cls.at(bounds, **options)
        return cls.disassemble(bb, **options)
    @utils.multicase(bb=idaapi.BasicBlock)
    @classmethod
    def disassemble(cls, bb, **options):
        '''Returns the disassembly of the basic block `bb`.'''
        F = functools.partial(database.disassemble, **options)
        return '\n'.join(map(F, cls.iterate(bb)))
    disasm = utils.alias(disassemble, 'block')

    @utils.multicase()
    @classmethod
    def call(cls):
        '''Return the operand reference of the call instruction in the current basic block.'''
        return cls.call(ui.current.address())
    @utils.multicase(ea=types.integer)
    @classmethod
    def call(cls, ea):
        '''Return the operand reference of the call instruction for the basic block at address `ea`.'''
        bb = cls.at(ea)
        return cls.call(bb)
    @utils.multicase(bounds=interface.bounds_t)
    @classmethod
    def call(cls, bounds):
        '''Return the operand reference of the call instruction for the basic block at the given `bounds`.'''
        left, right = bounds
        ea = idaapi.get_item_head(right - 1)

        # If the last instruction is not a call, then start scanning for one.
        if not interface.instruction.is_call(ea):
            ea = next((ea for ea in interface.address.items(left, right) if interface.instruction.is_call(ea)), ea)

        # If we couldn't get it this time, then give up and raise an exception.
        if not interface.instruction.is_call(ea):
            raise E.InstructionNotFoundError(u"{:s}.call({:s}) : Unable to find a call instruction at the expected address ({:#x}).".format('.'.join([__name__, cls.__name__]), bounds, ea))

        # Now our address should be pointing at a call instruction, so we just
        # need to return the operand reference for its target.
        return next(ref for ref in interface.instruction.access(ea) if 'x' in ref.access)
    @utils.multicase(bb=idaapi.BasicBlock)
    @classmethod
    def call(cls, bb):
        '''Return the operand reference of the call instruction for the basic block `bb`.'''
        FC_CALL_ENDS = getattr(idaapi, 'FC_CALL_ENDS', 0)
        fcpath = map(operator.attrgetter, ['_fc', '_q'])
        bounds = interface.range.bounds(bb)

        # Get the flowchart and check its flags to see if we can trust this block.
        try:
            fc = functools.reduce(lambda agg, item: item(agg), fcpath, bb)
            if not (fc.flags & FC_CALL_ENDS):
                raise AttributeError

        # If we couldn't get the flowchart to check the flags, then we hand
        # off to the case that uses a bounds_t to find the call within the block.
        except AttributeError:
            return cls.call(bounds)

        # Get the address of the block's last instruction and then check it.
        _, right = bounds
        ea = idaapi.get_item_head(right - 1)

        # If we couldn't find a call instruction, then bail with an exception.
        if not interface.instruction.is_call(ea):
            raise E.InstructionNotFoundError(u"{:s}.call({:s}) : Unable to find a call instruction at the expected address ({:#x}).".format('.'.join([__name__, cls.__name__]), bounds, ea))

        # Now we just need to figure out which operand it is and return it.
        return next(ref for ref in interface.instruction.access(ea) if 'x' in ref.access)

    @utils.multicase()
    @classmethod
    def branch(cls):
        '''Return the operand reference of the branch instruction in the current basic block.'''
        return cls.branch(ui.current.address())
    @utils.multicase(ea=types.integer)
    @classmethod
    def branch(cls, ea):
        '''Return the operand reference of the branch instruction for the basic block at address `ea`.'''
        bb = cls.at(ea)
        return cls.branch(bb)
    @utils.multicase(bounds=interface.bounds_t)
    @classmethod
    def branch(cls, bounds):
        '''Return the operand reference of the branch instruction for the basic block at the given `bounds`.'''
        left, right = bounds
        ea = idaapi.get_item_head(right - 1)

        # If the last instruction is not a branch, then start scanning for one.
        if not interface.instruction.is_branch(ea):
            ea = next((ea for ea in interface.address.items(left, right) if interface.instruction.is_branch(ea)), ea)

        # If we couldn't get it this time, then give up and raise an exception.
        if not interface.instruction.is_branch(ea):
            raise E.InstructionNotFoundError(u"{:s}.branch({:s}) : Unable to find a branch instruction at the expected address ({:#x}).".format('.'.join([__name__, cls.__name__]), bounds, ea))

        # Now our address should be pointing at a branch instruction, so we just
        # need to return the operand reference for its target.
        return next(ref for ref in interface.instruction.access(ea) if 'x' in ref.access)
    @utils.multicase(bb=idaapi.BasicBlock)
    @classmethod
    def branch(cls, bb):
        '''Return the operand reference of the branch instruction for the basic block `bb`.'''
        FC_CALL_ENDS = getattr(idaapi, 'FC_CALL_ENDS', 0)
        fcpath = map(operator.attrgetter, ['_fc', '_q'])
        bounds = interface.range.bounds(bb)

        # Get the flowchart and check its flags to see if we can trust this block.
        try:
            fc = functools.reduce(lambda agg, item: item(agg), fcpath, bb)
            if not (fc.flags & FC_CALL_ENDS):
                raise AttributeError

        # If we couldn't get the flowchart to check the flags, then we hand
        # off to the case that uses a bounds_t to find the branch within the block.
        except AttributeError:
            return cls.branch(bounds)

        # Get the address of the block's last instruction and then check it.
        _, right = bounds
        ea = idaapi.get_item_head(right - 1)

        # If we couldn't find a branch instruction, then bail with an exception.
        if not interface.instruction.is_branch(ea):
            raise E.InstructionNotFoundError(u"{:s}.branch({:s}) : Unable to find a branch instruction at the expected address ({:#x}).".format('.'.join([__name__, cls.__name__]), bounds, ea))

        # Now we just need to figure out which operand it is and return it.
        return next(ref for ref in interface.instruction.access(ea) if 'x' in ref.access)

    class type(object):
        """
        This namespace is for determining the type of a basic block in the
        ``idaapi.FlowChart`` belonging to a function. This is performed by
        returning attributes directly from instances of the ``idaapi.BasicBlock``
        type. In the author's opinion, most of the information attached to this
        object is thoroughly useless outside its associated graph. Despite this
        deficiency, some flags are exposed in case there's actual need for it.

        This namespace is also aliased as ``function.block.t``.
        """

        # FIXME: this namespace can definitely support cases other than `idaapi.BasicBlock`.

        # FIXME: we should implement a ton of the instruction types, such as .call(),
        #        .branchcc(), .branch(), .unconditional(), etc. fortunately, most of the
        #        instruction.type namespace already supports basic-blocks. however, it's more
        #        likely that a user would find those in this namespace rather than that one.

        @utils.multicase(bb=idaapi.BasicBlock)
        @classmethod
        def normal(cls, bb):
            '''Return whether the ``idaapi.BasicBlock`` identified by `bb` is a normal block with no special attributes.'''
            return bb.type in {interface.fc_block_type_t.fcb_normal}

        @utils.multicase(bb=idaapi.BasicBlock)
        @classmethod
        def linear(cls, bb):
            '''Return whether the ``idaapi.BasicBlock`` identified by `bb` is a block that will execute its next block linearly.'''
            return bb.type in {interface.fc_block_type_t.fcb_normal} and sum(1 for succ in bb.succs()) == 1

        @utils.multicase(bb=idaapi.BasicBlock)
        @classmethod
        def cyclic(cls, bb):
            '''Return whether the ``idaapi.BasicBlock`` identified by `bb` is a block that can branch to itself directly.'''
            return bb.type in {interface.fc_block_type_t.fcb_normal} and any(succ.id == bb.id for succ in bb.succs())

        @utils.multicase(bb=idaapi.BasicBlock)
        @classmethod
        def condition(cls, bb):
            '''Return whether the ``idaapi.BasicBlock`` identified by `bb` is a block that will execute its next block conditionally.'''
            return bb.type in {interface.fc_block_type_t.fcb_normal} and sum(1 for succ in bb.succs()) > 1

        @utils.multicase(bb=idaapi.BasicBlock)
        @classmethod
        def indirect(cls, bb):
            '''Return whether the ``idaapi.BasicBlock`` identified by `bb` is a block that will indirectly branch to another block.'''
            return bb.type in {interface.fc_block_type_t.fcb_indjump}

        @utils.multicase(bb=idaapi.BasicBlock)
        @classmethod
        def leave(cls, bb):
            '''Return whether the ``idaapi.BasicBlock`` identified by `bb` is a block that leaves its function.'''
            return bb.type in {interface.fc_block_type_t.fcb_ret}

        @utils.multicase(bb=idaapi.BasicBlock)
        @classmethod
        def leavecc(cls, bb):
            '''Return whether the ``idaapi.BasicBlock`` identified by `bb` is a block that conditionally leaves its function.'''
            return bb.type in {interface.fc_block_type_t.fcb_cndret}
        leavecondition = utils.alias(leavecc, 'block.type')

        @utils.multicase(bb=idaapi.BasicBlock)
        @classmethod
        def sentinel(cls, bb):
            '''Return whether the ``idaapi.BasicBlock`` identified by `bb` is a block that terminates execution of its function.'''
            return bb.type in {interface.fc_block_type_t.fcb_noret}

        @utils.multicase(bb=idaapi.BasicBlock)
        @classmethod
        def externalsentinel(cls, bb):
            '''Return whether the ``idaapi.BasicBlock`` identified by `bb` is an external block that terminates execution and does not belong to its function.'''
            return bb.type in {interface.fc_block_type_t.fcb_enoret}

        @utils.multicase(bb=idaapi.BasicBlock)
        @classmethod
        def external(cls, bb):
            '''Return whether the ``idaapi.BasicBlock`` identified by `bb` is an external block that continues execution and does not belong to its function.'''
            return bb.type in {interface.fc_block_type_t.fcb_extern}

        @utils.multicase(bb=idaapi.BasicBlock)
        @classmethod
        def error(cls, bb):
            '''Return whether the ``idaapi.BasicBlock`` identified by `bb` is an error block that continues execution outside its function.'''
            return bb.type in {interface.fc_block_type_t.fcb_error}

    t = type # XXX: ns alias

    # FIXME: implement .decompile for an idaapi.BasicBlock type too
    @utils.multicase()
    @classmethod
    def decompile(cls):
        '''(UNSTABLE) Returns the decompiled code of the basic block at the current address.'''
        return cls.decompile(ui.current.address())
    @utils.multicase(ea=types.integer)
    @classmethod
    def decompile(cls, ea):
        '''(UNSTABLE) Returns the decompiled code of the basic block at the address `ea`.'''
        source = idaapi.decompile(ea)

        res = map(functools.partial(operator.getitem, source.eamap), cls.iterate(ea))
        res = itertools.chain(*res)
        formatted = functools.reduce(lambda t, c: t if t[-1].ea == c.ea else t + [c], res, [next(res)])

        res = []
        # FIXME: This has been pretty damn unstable in my tests.
        try:
            for fmt in formatted:
                res.append( fmt.print1(source.__deref__()) )
        except TypeError: pass
        res = map(idaapi.tag_remove, res)
        return '\n'.join(map(utils.string.of, res))

class frame(object):
    """
    This namespace is for getting information about the frame from a selected
    function. By default, this namespace will return a ``structure_t``
    representing the frame belonging to the specified function. The offset of
    the returned frame will be relative to the stack pointer at the time the
    selected function was entered. This will result in offset 0 pointing at the
    preserved return address when the function was called.

    Some ways of using this can be::

        > print( function.frame() )
        > print( hex(function.frame.id(ea)) )
        > fr = function.frame.new(ea, 0x100, 8 * 4, regs=8)

    """
    @utils.multicase()
    def __new__(cls):
        '''Return the frame of the current function.'''
        return cls(ui.current.function())

    @utils.multicase(func=(idaapi.func_t, types.integer))
    def __new__(cls, func):
        '''Return the frame of the function `func`.'''
        fn = interface.function.by(func)
        if fn.frame == idaapi.BADNODE:
            raise E.MissingTypeOrAttribute(u"{:s}({:#x}) : The specified function does not have a frame.".format('.'.join([__name__, cls.__name__]), interface.range.start(fn)))
        return interface.function.frame(fn)

    class members(object):
        """
        This namespace is for interacting with the members from the frame for
        the selected function. It's primarily a wrapper around the functionality
        of the ``members_t`` class.
        """
        @utils.multicase()
        def __new__(cls, **type):
            '''Return the members for the frame belonging to the current function.'''
            return cls(ui.current.function())
        @utils.multicase(func=(idaapi.func_t, types.integer))
        def __new__(cls, func, **type):
            '''Return the members for the frame belonging to the function `func`.'''
            fn = interface.function.by(func)
            if fn.frame == idaapi.BADNODE:
                raise E.MissingTypeOrAttribute(u"{:s}({:#x}) : The specified function does not have a frame.".format('.'.join([__name__, cls.__name__]), interface.range.start(fn)))
            frame = interface.function.frame(fn)
            return frame.members(**type) if type else frame.members

        @utils.multicase()
        @classmethod
        def list(cls, **type):
            '''List the members from the frame belonging to the current function.'''
            return cls(ui.current.function()).list(**type)
        @utils.multicase()
        @classmethod
        def list(cls, func, **type):
            '''List the members from the frame belonging to the function `func`.'''
            return cls(func).list(**type)

        @utils.multicase()
        @classmethod
        def iterate(cls, **type):
            '''Iterate through the members in the frame belonging to the current function.'''
            return cls(ui.current.function()).iterate(**type)
        @utils.multicase()
        @classmethod
        def iterate(cls, func, **type):
            '''Iterate through the members in the frame belonging to the function `func`.'''
            return cls(func).iterate(**type)

    @utils.multicase()
    @classmethod
    def new(cls):
        '''Add an empty frame to the current function.'''
        fn = ui.current.function()
        return cls.new(fn, 0, idaapi.get_frame_retsize(fn), 0)
    @utils.multicase(func=(idaapi.func_t, types.integer))
    @classmethod
    def new(cls, func):
        '''Add an empty frame to the function `func`.'''
        fn = interface.function.by(func)
        return cls.new(fn, 0, idaapi.get_frame_retsize(fn), 0)
    @utils.multicase(lvars=types.integer, args=types.integer)
    @classmethod
    def new(cls, lvars, args, **regs):
        '''Add a frame to the current function using the sizes specified by `lvars` for local variables, and `args` for arguments.'''
        fn = ui.current.function()
        return cls.new(fn, lvars, regs.get('regs', idaapi.get_frame_retsize(fn)), args)
    @utils.multicase(func=(idaapi.func_t, types.integer), lvars=types.integer, args=types.integer)
    @classmethod
    def new(cls, func, lvars, args):
        '''Add a frame to the function `func` using the sizes specified by `lvars` for local variables, and `args` for arguments.'''
        fn = interface.function.by(func)
        return cls.new(fn, lvars, idaapi.get_frame_retsize(fn), args)
    @utils.multicase(func=(idaapi.func_t, types.integer), lvars=types.integer, regs=types.integer, args=types.integer)
    @classmethod
    def new(cls, func, lvars, regs, args):
        """Add a frame to the function `func` using the sizes specified by `lvars` for local variables, `regs` for frame registers, and `args` for arguments.

        When specifying the size of the registers (`regs`) the size of the saved instruction pointer must also be included.
        """
        fn = interface.function.by(func)
        _r = idaapi.get_frame_retsize(fn)
        ok = idaapi.add_frame(fn, lvars, regs - _r, args)
        if not ok:
            raise E.DisassemblerError(u"{:s}.new({:#x}, {:+#x}, {:+#x}, {:+#x}) : Unable to use `{:s}({:#x}, {:d}, {:d}, {:d})` to add a frame to the specified function.".format('.'.join([__name__, cls.__name__]), interface.range.start(fn), lvars, regs - _r, args, utils.pycompat.fullname(idaapi.add_frame), interface.range.start(fn), lvars, regs - _r, args))
        return interface.function.frame(fn)

    @utils.multicase()
    @classmethod
    def id(cls):
        '''Returns the structure id for the current function's frame.'''
        return cls.id(ui.current.function())
    @utils.multicase(func=(idaapi.func_t, types.integer))
    @classmethod
    def id(cls, func):
        '''Returns the structure id for the function `func`.'''
        fn = interface.function.by(func)
        return fn.frame

    class arguments(object):
        """
        This namespace is for returning information about the arguments
        within a function's frame. By default, this namespace will yield
        each argument as a tuple containing the `(offset, name, size)`.

        Some ways of using this are::

            > print( function.frame.arguments(f) )
            > print( function.frame.arguments.registers(f) )
            > print( function.frame.arguments.size(f) )
            > print( function.frame.arguments.location(ea) )

        """

        @utils.multicase()
        def __new__(cls):
            '''Yield the `(location, name, tags)` of each argument relative to the stack pointer at the entry point of the current function.'''
            return cls(ui.current.address())
        @utils.multicase(func=(idaapi.func_t, types.integer))
        def __new__(cls, func):
            '''Yield the `(location, name, tags)` of each argument relative to the stack pointer at the entry point of the function `func`.'''
            _, ea = interface.addressOfRuntimeOrStatic(func)
            fn = idaapi.get_func(ea)

            # first we'll need to check if there's a tinfo_t for the address to
            # give it priority over the frame. then we can grab its details.
            if type.has(ea):
                tinfo, ftd = interface.tinfo.function_details(ea)

                # iterate through the parameters and collect only arguments that
                # are allocated on the stack so that we can use their information
                # when yielding our results.
                items = []
                for index in builtins.range(ftd.size()):
                    arg, loc = ftd[index], ftd[index].argloc

                    # not allocated on the stack? then we skip it..
                    if loc.atype() != idaapi.ALOC_STACK:
                        continue

                    # extract the raw location, and then add the argument
                    # information that we collected to our list.
                    items.append((index, interface.tinfo.location_raw(loc), utils.string.of(arg.name), interface.tinfo.copy(arg.type)))

                # our results shouldn't have duplicates, but they might. actually,
                # our results could technically be overlapping too. still, this is
                # just to priority the tinfo_t and we only care about the offset.
                locations = {}
                for index, rawlocation, name, tinfo in items:
                    location = interface.tinfo.location(tinfo.get_size(), instruction.architecture, *rawlocation)
                    moffset, msize = mlocation = location + idaapi.get_frame_retsize(fn)
                    if operator.contains(locations, moffset):
                        old_index, old_name, _ = locations[moffset]
                        logging.warning(u"{:s}({:#x}) : Overwriting the parameter {:s}(index {:d}) for function ({:#x}) due to parameter {:s}(index {:d}) being allocated at the same frame offset ({:+#x}).".format('.'.join([__name__, cls.__name__]), ea, "\"{:s}\" ".format(utils.string.escape(old_name, '"')) if old_name else '', old_index, ea, "\"{:s}\" ".format(utils.string.escape(name, '"')) if name else '', index, moffset))

                    locations[moffset] = (index, name, tinfo, mlocation)

                # that was it, we have our locations and we can proceed.
                locations = locations

            # if there was no type information, then we have no locations to reference.
            else:
                locations = {}

            # now we need to check if our address actually includes a frame. if it
            # doesn't, then we need to explicitly process our locations here.
            fr, results = idaapi.get_frame(ea), []
            if fr is None:
                items = [offset for offset in locations]

                # before we do anything, we need to figure out our lowest offset
                # so that we can return the unnamed members that will exist in
                # between our $pc and any actual args allocated on the stack.
                delta = min(locations) if locations else 0
                if delta:
                    results.append((interface.location_t(0, delta), None, {}))

                # now we can iterate through all our locations and yield each one.
                for offset in sorted(locations):
                    _, name, ti, location = locations[offset]
                    tags = {}   # FIXME: tinfo_t has comments, we should grab the tags jic
                    results.append((loc, name or None, tags))
                return results

            # to proceed, we need to know the function to get its frame sizes.
            else:
                fn = idaapi.get_func(ea)

            # once we have our locations, we can grab a fragment from the frame
            # and yield all of the members that are considered as arguments.
            current = 0
            for sptr, mindex, mptr in internal.structure.members.at_bounds(fr.id, idaapi.frame_off_args(fn), idaapi.get_struc_size(fr)):
                offset = interface.function.frame_offset(fn, mptr.soff)
                size, mtags = (F(mptr) for F in [idaapi.get_member_size, internal.tags.member.get])

                # check our locations to see if we have any type information
                # for the given offset so that way we can prioritize it.
                if offset in locations:
                    index, tname, tinfo, location = locations.pop(offset)

                    # grab the tinfo name and tinfo size. if the name wasn't found,
                    # then fall back to using the member name from the frame.
                    name = tname or internal.structure.member.get_name(mptr)
                    toffset, tsize = location

                    # if our member size matches our tinfo size, then we can yield it.
                    if tsize == size:
                        results.append((location, name, mtags))

                    # if the tinfo size is smaller then the member's, then we're
                    # going to need to pad it up to the expected member size.
                    elif tsize < size:
                        results.append((location, name, mtags))
                        results.append((interface.location_t(toffset + tsize, size - tsize), None, {}))

                    # otherwise, the member size is smaller than the tinfo size.
                    # if this is the case, then we need to use the member size
                    # but log a warning that we're ignoring the size of the tinfo.
                    else:
                        logging.warning(u"{:s}({:#x}) : Ignoring the type size for parameter {:s}(index {:d}) for function ({:#x}) due to the frame member at offset ({:+#x}) being smaller ({:+#x}).".format('.'.join([__name__, cls.__name__]), ea, "\"{:s}\" ".format(utils.string.escape(tname, '"')) if tname else '', index, ea, offset, size))
                        results.append((interface.location_t(offset, size), name, mtags))
                        results.append((interface.location_t(offset + size, tsize - size), None, {}))

                # otherwise we'll just yield the information from the member.
                else:
                    results.append((interface.location_t(offset, size), internal.structure.member.get_name(mptr), mtags))

                # update our current offset and proceed to the next member.
                current = offset + size

            # iterate through all of the locations that we have left.
            for offset in sorted(locations):
                _, name, ti, location = locations[offset]

                # if our current position is not pointing at the expected offset,
                # then we need to yield some padding that will put us there.
                if current < offset:
                    results.append((interface.location_t(current, offset - current), None, {}))

                # now we can yield the next member and adjust our current position.
                results.append((location, name or None, {}))
                current = offset + ti.get_size()
            return results

        @utils.multicase()
        @classmethod
        def location(cls):
            '''Return the list of address locations for each of the parameters that are passed to the function call at the current address.'''
            return cls.location(ui.current.address())
        @utils.multicase(ea=types.integer)
        @classmethod
        def location(cls, ea):
            '''Return the list of address locations for each of the parameters that are passed to the function call at `ea`.'''
            iterable = interface.instruction.arguments(ea)
            return [ea for ea in iterable]
        @utils.multicase(ea=types.integer, index=types.integer)
        @classmethod
        def location(cls, ea, index):
            '''Return the initialization address for the parameter at `index` for the function call at `ea`.'''
            items = interface.instruction.arguments(ea)
            if 0 <= index < len(items):
                return items[index]
            raise E.InvalidTypeOrValueError(u"{:s}.location({:#x}, {:d}) : The requested argument index ({:d}) for the function reference at address {:#x} is outside the number of available arguments ({:d} <= {:d} < {:d}).".format('.'.join([__name__, cls.__name__]), ea, index, index, ea, 0, index, len(items)))
        locations = utils.alias(location, 'frame.args')

        @utils.multicase()
        @classmethod
        def iterate(cls):
            '''Yield the `(member, type, name)` associated with the arguments for the current function.'''
            return cls.iterate(ui.current.address())
        @utils.multicase(func=(idaapi.func_t, types.integer))
        @classmethod
        def iterate(cls, func):
            '''Yield the `(member, type, name)` associated with the arguments for the function `func`.'''
            rt, ea = interface.addressOfRuntimeOrStatic(func)
            fn, has_tinfo = None if rt else interface.function.by_address(ea), interface.function.has_typeinfo(ea)

            # We need our frame to be correct, so we confirm it by checking the problem queue.
            Fproblem = builtins.next((getattr(idaapi, candidate) for candidate in ['is_problem_present', 'QueueIsPresent'] if hasattr(idaapi, candidate)), utils.fconstant(False))
            PR_BADSTACK = getattr(idaapi, 'PR_BADSTACK', 0xb)

            # Build a lookup table that we'll use to deserialize the correct type for each size.
            bits, byte = interface.database.bits(), idaapi.tinfo_t()
            tilookup = {
                8: idaapi.BT_INT8, 16: idaapi.BT_INT16, 32: idaapi.BT_INT32,
                64: idaapi.BT_INT64, 128: idaapi.BT_INT128, 80: idaapi.BTF_TBYTE,
            }
            byte.create_simple_type(idaapi.BTF_BYTE)

            # If we have type information that we can grab from the given address,
            # then we can use it to rip out the details and locate each member.
            if has_tinfo:
                tinfo, ftd = interface.tinfo.function_details(ea)

                # Now we just need to iterate through our parameters collecting the
                # raw location information for all of them. We preserve the type
                # information in case we're unable to find the argument in a member.
                items = []
                for index in builtins.range(ftd.size()):
                    arg, aloc = ftd[index], ftd[index].argloc
                    items.append((index, utils.string.of(arg.name), interface.tinfo.copy(arg.type), interface.tinfo.location_raw(aloc)))

                # Last thing that we need to do is to extract each location and
                # figure out whether we return it as a location or an actual member.
                fr = None if rt else frame(ea) if idaapi.get_frame(ea) else None
                for index, aname, atype, ainfo in items:
                    aloc = interface.tinfo.location(atype.get_size(), instruction.architecture, *ainfo)

                    # If it's a location, then we need to translate it to find out
                    # where the member is actually located at. This becomes our result
                    # if we have a frame. Otherwise, we just return the location as-is.
                    if isinstance(aloc, interface.location_t):
                        aoffset, asize = aloc
                        moffset = aoffset + idaapi.frame_off_args(fn)
                        offset, nameoffset = (F(fn, moffset) for F in [interface.function.frame_offset, interface.function.frame_member_offset])
                        location = interface.location_t(offset, asize)

                        # Use the translated offset to find the correct member. If we
                        # couldn't find one, then use the location as the member. We
                        # also assign the member name, giving it priority over the type.
                        try:
                            mem = fr.members.by(offset) if fr else location
                        except (E.MemberNotFoundError, E.OutOfBoundsError):
                            mem, mname = location, aname
                        else:
                            mname = mem.name or aname if fr else aname

                        # Now we can yield the member/location, the type and its name.
                        yield mem, atype, mname or interface.tuplename('arg', nameoffset)

                    # If it's a tuple, then we check if it contains any registers
                    # so that way we can process them if necessary. If its a register
                    # offset where its second item is an integer and it's zero, then
                    # we can simply exclude the offset from our results.
                    elif isinstance(aloc, types.tuple) and any(isinstance(item, interface.register_t) for item in loc):
                        reg, offset = aloc
                        yield aloc if offset else reg, atype, aname

                    # Otherwise, it's one of the custom locations that we don't
                    # support. So we can just return it as we received it.
                    else:
                        yield aloc, atype, aname
                    continue
                return

            # If we have no type information, then we can only process arguments if we're within
            # a function. If we're not not part of a functon, then we log a warning and bail.
            elif not fn:
                logging.warning(u"{:s}.iterate({:#x}) : Unable to iterate through the arguments for the given function ({:#x}) due to missing type information and frame.".format('.'.join([__name__, cls.__name__]), ea, ea))
                return

            # Otherwise, we have no type information and we'll need to extract things
            # directly from the func_t. We start out by checking if regarqty is larger
            # than zero so that we can yield any registers that the disassembler found.
            if fn.regargqty:
                registers = []

                # If regargqty is set, but regargs is None...then we need to call read_regargs on our
                # fn to get IDA to actually read it...The funny thing is, on earlier versions of IDA
                # it seems that read_regargs won't always allocate an iterator...so this means that
                # we manually make it a list and then this way we can iterate through the fucker.
                idaapi.read_regargs(fn) if fn.regargs is None else None
                if isinstance(fn.regargs, idaapi.regarg_t):
                    regargs = [fn.regargs]
                else:
                    regargs = [fn.regargs[index] for index in builtins.range(fn.regargqty)]

                # Iterate through all of our arguments in order to grab the register,
                # the type information, and argument name out of the register argument.
                for index, regarg in enumerate(regargs):
                    rreg, rtype, rname = regarg.reg, regarg.type, utils.string.of(regarg.name)
                    reg = instruction.architecture.by_index(rreg) if instruction.architecture.has(rreg) else None
                    rsize = reg.size if reg else 0

                    # Deserialize the type information that we received from the register argument.
                    ti = interface.tinfo.get(None, rtype)
                    if not ti and operator.contains(tilookup, bits):
                        ti = interface.tinfo.get(None, bytes(bytearray([tilookup[bits]])))

                    # If we failed creating a type of the correct size, then we fall back to an
                    # array that uses the register size so that we at least get the size correct.
                    atd, array_t = idaapi.array_type_data_t(), idaapi.tinfo_t()
                    atd.base, atd.nelems, atd.elem_type = 0, rsize, byte
                    if not ti and reg and array_t.create_array(atd):
                        ti = interface.tinfo.concretize(array_t)
                        logging.warning(u"{:s}.iterate({:#x}) : Using the placeholder type \"{:s}\" due to being unable to decode the type information ({!r}) for the argument at index {:d}.".format('.'.join([__name__, cls.__name__]), ea, utils.string.escape("{!s}".format(ti), '"'), rtype, index))

                    # If we _still_ don't have a type, then we issue a warning and substitute a void*
                    # for the type. This should always result in the correct default register size.
                    voidstar = interface.tinfo.get(None, bytes(bytearray([idaapi.BT_PTR, idaapi.BT_VOID])))
                    if not ti and voidstar:
                        ti = voidstar
                        logging.warning(u"{:s}.iterate({:#x}) : Falling back to the placeholder type \"{:s}\" due to being unable to cast the type information ({!r}) to an array ({:d}) for the argument at index {:d}.".format('.'.join([__name__, cls.__name__]), ea, utils.string.escape("{!s}".format(ti), '"'), rtype, rsize, index))

                    # If we couldn't create a void* type, then this is a critical failure that needs
                    # to get logged. We still add it, though, so that the register can be yielded.
                    elif not ti:
                        logging.critical(u"{:s}.iterate({:#x}) : Unable to find a type of the correct size ({:d}) for register argument at index {:d} ({!s}) using the given type information ({!r}).".format('.'.join([__name__, cls.__name__]), ea, rsize, index, reg, rtype))

                    # Now we can add everything that was determined to our list for processing.
                    registers.append((reg, ti, rname))

                # Now that we have the register, its tinfo_t, and the type. We do one final
                # pass to correct the register size according to the type that was determined.
                for reg, rtype, rname in registers:
                    try:
                        reg = instruction.architecture.by_indexsize(reg.id, rtype.get_size())

                    # If there was no type, then yield a non-present type.
                    except KeyError:
                        yield reg, rtype or idaapi.tinfo_t(), rname or None
                    else:
                        yield reg, rtype or idaapi.tinfo_t(), rname or None
                    continue

                # We've processed the registers, so we can fall-through for the other paramters.

            # If we don't have a frame, then there's nothing more we can do.
            sptr = idaapi.get_frame(fn) if fn else None
            if not sptr:
                return

            # If we do have a frame, then we do our best to figure out the parameters from it.
            fr = interface.function.frame(fn)

            # Now we can grab the fragment of the structure containing the parameters.
            for mowner, mindex, mptr in internal.structure.members.at_bounds(fr.id, idaapi.frame_off_args(fn), idaapi.get_struc_size(sptr)):
                aoffset = interface.function.frame_offset(fn, mptr.soff)
                asize = idaapi.get_member_size(mptr)
                aname = internal.structure.member.get_name(mptr) or internal.structure.member.default_name(fr, mptr)
                location = interface.location_t(aoffset, asize)

                # Pre-create an array_type_data_t so that we can create a type if it is missing.
                atd = idaapi.array_type_data_t()
                atd.base, atd.nelems, atd.elem_type = 0, asize, byte

                atype = idaapi.tinfo_t()
                if not atype.create_array(atd):
                    raise E.DisassemblerError(u"{:s}.iterate({:#x}) : Unable to create an array of the required number of bytes ({:d}).".format('.'.join([__name__, cls.__name__]), ea, asize))

                # Now we can just use the index to fetch the member to return. We also extract the
                # type information, so that we can create it if the member is missing its type.
                mem = fr.members[mindex]
                mtype = internal.structure.member.get_typeinfo(mptr)

                # If we have some type information, then we can just yield everything as-is.
                if mtype:
                    yield mem, mtype, aname

                # If there isn't a type, then we try to find one that matches the member size.
                elif operator.contains(tilookup, 8 * asize) and interface.tinfo.get(None, bytes(bytearray([tilookup[8 * asize]]))):
                    yield mem, interface.tinfo.get(None, bytes(bytearray([tilookup[8 * asize]]))), aname

                # Otherwise, we use the array that we created earlier for the member type.
                else:
                    yield mem, interface.tinfo.concretize(atype), aname
                continue
            return

        @utils.multicase()
        @classmethod
        def registers(cls):
            '''Return the `(register, type, name)` associated with the arguments of the current function as a list.'''
            return cls.registers(ui.current.address())
        @utils.multicase(func=(idaapi.func_t, types.integer))
        @classmethod
        def registers(cls, func):
            '''Return the `(register, type, name)` associated with the arguments of the function `func` as a list.'''
            result = []
            for apacked in cls.iterate(func):
                areg, atype, name = apacked
                if isinstance(areg, interface.register_t):
                    result.append(apacked)
                elif isinstance(arg, types.tuple) and all(isinstance(item, interface.register_t) for item in areg):
                    result.append(apacked)
                continue
            return result
        regs = utils.alias(registers, 'frame.args')

        @utils.multicase()
        @classmethod
        def size(cls):
            '''Returns the size of the arguments for the current function.'''
            return cls.size(ui.current.function())
        @utils.multicase(func=(idaapi.func_t, types.integer))
        @classmethod
        def size(cls, func):
            '''Returns the size of the arguments for the function `func`.'''
            fn = interface.function.by(func)
            sptr = idaapi.get_frame(fn)
            if fn.frame == idaapi.BADNODE or not sptr:
                return 0
            return idaapi.get_struc_size(sptr.id) - sum(F(fn) for F in [frame.variables.size, frame.registers.size])
    args = arg = arguments  # XXX: ns alias

    class variables(object):
        """
        This namespace provides information about the local variables
        within the frame of a function as constructed by its prologue.

        Some ways to get this information can be::

            > print( function.frame.variables.size() )

        """
        @utils.multicase()
        def __new__(cls):
            '''Yield the `(location, name, tags)` of each local variable relative to the stack pointer at the entry point for the current function.'''
            return cls(ui.current.address())
        @utils.multicase(func=(idaapi.func_t, types.integer))
        def __new__(cls, func):
            '''Yield the `(location, name, tags)` of each local variable relative to the stack pointer at the entry point for the function `func`.'''
            fn = interface.function.by(func)

            # figure out the frame
            fr = idaapi.get_frame(fn)
            if fr is None:  # unable to figure out arguments
                raise E.MissingTypeOrAttribute(u"{:s}({:#x}) : Unable to get the function frame.".format('.'.join([__name__, cls.__name__]), interface.range.start(fn)))

            results = []
            for sptr, mindex, mptr in internal.structure.members.at_bounds(fr.id, 0, fn.frsize):
                offset = interface.function.frame_offset(fn, mptr.soff)
                mname, mtags = (F(mptr) for F in [internal.structure.member.get_name, internal.tags.member.get])
                location = interface.location_t(offset, idaapi.get_member_size(mptr))
                results.append((location, mname, mtags))
            return results

        @utils.multicase()
        @classmethod
        def size(cls):
            '''Returns the size of the local variables for the current function.'''
            fn = interface.function.by(ui.current.function())
            return fn.frsize
        @utils.multicase(func=(idaapi.func_t, types.integer))
        @classmethod
        def size(cls, func):
            '''Returns the size of the local variables for the function `func`.'''
            fn = interface.function.by(func)
            return fn.frsize
    lvars = vars = variables    # XXX: ns alias

    class registers(object):
        """
        This namespace provides information about the registers that are
        preserved in the prologue when a function constructs its frame.

        An example of using this namespace::

            > print( function.frame.registers.size(ea) )

        """

        @utils.multicase()
        def __new__(cls):
            '''Yield the `(location, name, tags)` of each preserved register relative to the stack pointer at the entry point of the current function.'''
            return cls(ui.current.address())
        @utils.multicase(func=(idaapi.func_t, types.integer))
        def __new__(cls, func):
            '''Yield the `(location, name, tags)` of each preserved register relative to the stack pointer at the entry point of the function `func`.'''
            fn = interface.function.by(func)

            # figure out the frame
            fr = idaapi.get_frame(fn)
            if fr is None:  # unable to figure out arguments
                raise E.MissingTypeOrAttribute(u"{:s}({:#x}) : Unable to get the function frame.".format('.'.join([__name__, cls.__name__]), interface.range.start(fn)))

            results, offset = [], idaapi.frame_off_savregs(fn)
            for sptr, mindex, mptr in internal.structure.members.at_bounds(fr.id, offset, offset + interface.function.frame_registers(fn)):
                offset = interface.function.frame_offset(fn, mptr.soff)
                mname, mtags = (F(mptr) for F in [internal.structure.member.get_name, internal.tags.member.get])
                location = interface.location_t(offset, idaapi.get_member_size(mptr))
                results.append((location, mname, mtags))
            return results

        @utils.multicase()
        @classmethod
        def size(cls):
            '''Returns the number of bytes occupied by the preserved registers in the current function.'''
            return interface.function.frame_registers(ui.current.function())
        @utils.multicase(func=(idaapi.func_t, types.integer))
        @classmethod
        def size(cls, func):
            '''Returns the number of bytes occupied by the preserved registers for the function `func`.'''
            return interface.function.frame_registers(func)
    regs = registers    # XXX: ns alias

get_frameid = utils.alias(frame.id, 'frame')
get_args_size = utils.alias(frame.args.size, 'frame.args')
get_vars_size = utils.alias(frame.variables.size, 'frame.variables')
get_regs_size = utils.alias(frame.registers.size, 'frame.registers')

## instruction iteration/searching
## tagging
@utils.multicase()
def tag():
    '''Returns all the tags defined for the current function.'''
    return internal.tags.function.get(ui.current.address())
@utils.multicase(key=types.string)
@utils.string.decorate_arguments('key')
def tag(key):
    '''Returns the value of the tag identified by `key` for the current function.'''
    return tag(ui.current.address(), key)
@utils.multicase(key=types.string)
@utils.string.decorate_arguments('key', 'value')
def tag(key, value):
    '''Sets the value for the tag `key` to `value` for the current function.'''
    return internal.tags.function.set(ui.current.address(), key, value)
@utils.multicase(func=(idaapi.func_t, types.integer), key=types.string)
@utils.string.decorate_arguments('key')
def tag(func, key):
    '''Returns the value of the tag identified by `key` for the function `func`.'''
    res = internal.tags.function.get(func)
    if key in res:
        return res[key]
    raise E.MissingFunctionTagError(u"{:s}.tag({:s}, {!r}) : Unable to read the specified tag (\"{:s}\") from the function.".format(__name__, ("{:#x}" if isinstance(func, types.integer) else "{!r}").format(func), key, utils.string.escape(key, '"')))
@utils.multicase(func=(idaapi.func_t, types.integer))
def tag(func):
    '''Returns all the tags defined for the function `func`.'''
    return internal.tags.function.get(func)
@utils.multicase(func=(idaapi.func_t, types.integer), key=types.string)
@utils.string.decorate_arguments('key', 'value')
def tag(func, key, value):
    '''Sets the value for the tag `key` to `value` for the function `func`.'''
    return internal.tags.function.set(func, key, value)
@utils.multicase(key=types.string, none=types.none)
@utils.string.decorate_arguments('key')
def tag(key, none):
    '''Removes the tag identified by `key` for the current function.'''
    return internal.tags.function.remove(ui.current.address(), key, none)
@utils.multicase(func=(idaapi.func_t, types.integer), key=types.string, none=types.none)
@utils.string.decorate_arguments('key')
def tag(func, key, none):
    '''Removes the tag identified by `key` from the function `func`.'''
    return internal.tags.function.remove(func, key, none)

@utils.multicase()
def tags():
    '''Returns all of the content tags for the function at the current address.'''
    return tags(ui.current.address())
@utils.multicase(ea=types.integer)
def tags(ea):
    '''Returns all of the content tags for the function at the address `ea`.'''
    fn, owners = interface.function.by(ea), {item for item in interface.function.owners(ea)}

    # If we have multiple owners, then consolidate all of their tags into a set.
    if len(owners) > 1:
        logging.warning(u"{:s}.tags({:#x}) : Returning all of the tags for the functions owning the given address ({:#x}) as it is owned by multiple functions ({:s}).".format(__name__, ea, ea, ', '.join(map("{:#x}".format, owners))))
        return {item for item in itertools.chain(*map(tags, owners))}

    # If we have only one owner, then we just need to point ourselves at it.
    item, = owners

    # Although if the chunk address wasn't in the owner list, then warn the user that we fixed it.
    if interface.range.start(fn) not in owners:
        logging.warning(u"{:s}.tags({:#x}) : Returning the tags for the function at address ({:#x}) as the chunk address ({:#x}) is not referencing a function ({:s}).".format(__name__, ea, item, interface.range.start(fn), ', '.join(map("{:#x}".format, owners))))
    return internal.tagcache.contents.name(item, target=item)
@utils.multicase(func=(idaapi.func_t, types.string))
def tags(func):
    '''Returns all of the content tags for the function `func`.'''
    fn = interface.function.by(func)
    ea = interface.range.start(fn)
    return tags(ea)

@utils.multicase()
@utils.string.decorate_arguments('And', 'Or', 'require', 'requires', 'required', 'include', 'includes', 'included')
def select(**boolean):
    '''Query the contents of the current function for any tags specified by `boolean`'''
    return select(ui.current.function(), **boolean)
@utils.multicase(tag=types.string)
@utils.string.decorate_arguments('tag', 'And', 'Or', 'require', 'requires', 'required', 'include', 'includes', 'included')
def select(tag, *required, **boolean):
    '''Query the contents of the current function for the given `tag` and any others that should be `required` or `included`.'''
    res = {tag} | {item for item in required}
    boolean['required'] = {item for item in boolean.get('required', [])} | res
    return select(ui.current.function(), **boolean)
@utils.multicase(func=(idaapi.func_t, types.integer), tag=types.string)
@utils.string.decorate_arguments('tag', 'And', 'Or', 'require', 'requires', 'required', 'include', 'includes', 'included')
def select(func, tag, *required, **boolean):
    '''Query the contents of the function `func` for the given `tag` and any others that should be `required` or `included`.'''
    res = {tag} | {item for item in required}
    boolean['required'] = {item for item in boolean.get('required', [])} | res
    return select(func, **boolean)
@utils.multicase(func=(idaapi.func_t, types.integer), tags=types.unordered)
@utils.string.decorate_arguments('tags', 'And', 'Or', 'require', 'requires', 'required', 'include', 'includes', 'included')
def select(func, tags, *required, **boolean):
    '''Query the contents of the function `func` for the given `tags` and any others that should be `required` or `included`.'''
    res = {item for item in tags} | {item for item in required}
    boolean['required'] = {item for item in boolean.get('required', [])} | res
    return select(func, **boolean)
@utils.multicase(func=(idaapi.func_t, types.integer))
@utils.string.decorate_arguments('And', 'Or', 'require', 'requires', 'required', 'include', 'includes', 'included')
def select(func, **boolean):
    """Query the contents of the function `func` for any of the tags specified by `boolean and yield a tuple for each matching address with selected tags.

    If `require` is given as an iterable of tag names then require that each returned address uses them.
    If `include` is given as an iterable of tag names then include the tags for each returned address if available.
    """
    target = interface.function.by(func)
    boolean = {key : {item for item in value} if isinstance(value, types.unordered) else {value} for key, value in boolean.items()}

    # If something was specified to query, then collect all of the selected
    # tagnames and use them as parameters with the `internal.tags.select`
    # function. Otherwise, we can just avoid them to get everything.
    if boolean:
        included, required = ({item for item in itertools.chain(*(boolean.get(B, []) for B in Bs))} for Bs in [['Or', 'include', 'included', 'includes'], ['And', 'require', 'required', 'requires']])
        return internal.tags.select.function(target, required, included)
    return internal.tags.select.function(target)

@utils.multicase()
def switches():
    '''Yield each switch found in the current function.'''
    return switches(ui.current.function())
@utils.multicase(func=(idaapi.func_t, types.integer))
def switches(func):
    '''Yield each switch found in the function identifed by `func`.'''
    get_switch_info = idaapi.get_switch_info_ex if idaapi.__version__ < 7.0 else idaapi.get_switch_info
    for ea in iterate(func):
        si = get_switch_info(ea)
        if si: yield interface.switch_t(si)
    return

class type(object):
    """
    This namespace allows one to query type information about a
    specified function. This allows one to get any attributes that IDA
    or a user has applied to a function within the database. This alows
    one to filter functions according to their particular attributes.

    This namespace is aliased as ``function.t``.

    Some of the functions within this namespace are also aliased as
    the following globals:

        ``function.convention`` - Interact with the calling convention (``idaapi.CM_CC_*``) for a function's prototype.
        ``function.result`` - Interact with the result type associated with a function's prototype.

    Some simple ways of getting information about a function::

        > print( function.type.frame() )
        > for ea in filter(function.type.library, database.functions()): ...

    """
    @utils.multicase()
    def __new__(cls):
        '''Return the type information for the current function as an ``idaapi.tinfo_t``.'''
        return cls(ui.current.address())
    @utils.multicase(info=(types.string, idaapi.tinfo_t))
    def __new__(cls, info, **guessed):
        '''Apply the type information in `info` to the current function.'''
        return cls(ui.current.address(), info, **guessed)
    @utils.multicase(none=types.none)
    def __new__(cls, none):
        '''Remove the type information for the current function.'''
        return cls(ui.current.address(), None)
    @utils.multicase(func=(types.integer, idaapi.func_t))
    def __new__(cls, func):
        '''Return the type information for the function `func` as an ``idaapi.tinfo_t``.'''
        ti = interface.function.typeinfo(func)
        if ti is None:
            _, ea = interface.addressOfRuntimeOrStatic(func)
            raise E.DisassemblerError(u"{:s}({:#x}) : Unable to create a function type to return for the specified address ({:#x}).".format('.'.join([__name__, cls.__name__]), ea, ea))
        return ti
    @utils.multicase(func=(idaapi.func_t, types.integer), info=idaapi.tinfo_t)
    def __new__(cls, func, info, **guessed):
        '''Apply the ``idaapi.tinfo_t`` in `info` to the function `func`.'''
        TINFO_GUESSED, TINFO_DEFINITE = getattr(idaapi, 'TINFO_GUESSED', 0), getattr(idaapi, 'TINFO_DEFINITE', 1)

        # First figure out whether we're adjusting with the type or explicitly changing it.
        iterable = (guessed[kwd] for kwd in ['guess', 'guessed'] if kwd in guessed)
        flags = [TINFO_GUESSED if builtins.next(iterable, False) else TINFO_DEFINITE] if any(kwd in guessed for kwd in ['guess', 'guessed']) else []

        # Now we can figure out what address we're actually working with.
        rt, ea = interface.addressOfRuntimeOrStatic(func)

        # If the type is not a function type whatsoever, then bail.
        if not any([info.is_func(), info.is_funcptr()]):
            raise E.InvalidTypeOrValueError(u"{:s}({:#x}, {!r}) : Refusing to apply a non-function type ({!r}) to the given {:s} ({:#x}).".format('.'.join([__name__, cls.__name__]), ea, "{!s}".format(info), 'address' if rt else 'function', ea))

        # If we're being used against an export, then we need to make sure that
        # our type is a function pointer and we need to promote it if not.
        ti = interface.function.pointer(info) if rt else info
        if rt and ti is None:
            raise E.DisassemblerError(u"{:s}({:#x}, {!r}) : Unable to promote type to a pointer as required when applying a function type to a runtime-linked address ({:#x}).".format('.'.join([__name__, cls.__name__]), ea, "{!s}".format(info), ea))

        elif ti is not info:
            logging.warning(u"{:s}({:#x}, {!r}) : Promoted type ({!r}) to a function pointer ({!r}) due to the address ({:#x}) being runtime-linked.".format('.'.join([__name__, cls.__name__]), ea, "{!s}".format(info), "{!s}".format(info), "{!s}".format(ti), ea))

        # and then we just need to apply the type to the given address.
        result, ok = interface.function.typeinfo(ea), interface.function.apply_typeinfo(ea, ti, *flags)
        if not ok:
            raise E.DisassemblerError(u"{:s}({:#x}, {!r}) : Unable to apply typeinfo ({!r}) to the {:s} ({:#x}).".format('.'.join([__name__, cls.__name__]), ea, "{!s}".format(info), "{!s}".format(ti), 'address' if rt else 'function', ea))
        return result
    @utils.multicase(func=(idaapi.func_t, types.integer), info=types.string)
    @utils.string.decorate_arguments('info')
    def __new__(cls, func, info, **guessed):
        '''Parse the type information string in `info` into an ``idaapi.tinfo_t`` and apply it to the function `func`.'''
        MNG_NODEFINIT, MNG_NOPTRTYP, MNG_LONG_FORM = getattr(idaapi, 'MNG_NODEFINIT', 8), getattr(idaapi, 'MNG_NOPTRTYP', 7), getattr(idaapi, 'MNG_LONG_FORM', 0x6400007)
        parseflags = functools.reduce(operator.or_, [idaapi.PT_SIL, idaapi.PT_VAR, idaapi.PT_LOWER, idaapi.PT_NDC])

        # Figure out what we're actually going to be applying the type information to,
        # and figure out what its real name is so that we can mangle it if necessary.
        rt, ea = interface.addressOfRuntimeOrStatic(func)

        fname, mangled = interface.function.name(ea), interface.name.get(ea) if rt else utils.string.of(idaapi.get_func_name(ea))
        if fname and interface.name.mangled(ea, mangled) != idaapi.FF_UNK:
            realname = utils.string.of(idaapi.demangle_name(utils.string.to(mangled), MNG_NODEFINIT|MNG_NOPTRTYP) or fname)
        else:
            realname = fname

        # Now we can parse it and see what we have. If we couldn't parse it or it
        # wasn't an actual function of any sort, then we need to bail.
        packed = interface.tinfo.parse(None, info, parseflags)
        parsedname, ti = packed if packed else (realname, None)
        if not ti:
            raise E.InvalidTypeOrValueError(u"{:s}({:#x}, {!r}) : Unable to parse the provided string \"{!s}\" as a properly named function prototype.".format('.'.join([__name__, cls.__name__]), ea, info, utils.string.escape(info, '"')))

        elif not any([ti.is_func(), ti.is_funcptr()]):
            raise E.InvalidTypeOrValueError(u"{:s}({:#x}, {!r}) : Refusing to apply a non-prototype (\"{!s}\") to the given {:s} ({:#x}).".format('.'.join([__name__, cls.__name__]), ea, info, utils.string.escape(info, '"'), 'address' if rt else 'function', ea))

        # Otherwise, the type is valid and we only need to figure
        # out if it needs to be promoted to a pointer or not.
        newti = interface.function.pointer(ti) if rt else ti
        if rt and not newti:
            raise E.DisassemblerError(u"{:s}({:#x}, {!r}) : Unable to promote type to a pointer as required when applying a function type to a runtime-linked address ({:#x}).".format('.'.join([__name__, cls.__name__]), ea, info, ea))

        elif newti is not ti:
            logging.warning(u"{:s}({:#x}, {!r}) : Promoting type \"{:s}\" to a function pointer ({!r}) due to the address ({:#x}) being runtime-linked.".format('.'.join([__name__, cls.__name__]), ea, info, utils.string.escape(ti, '"'), "{!s}".format(newti), ea))

        # Now we re-render the type into a string in case we couldn't apply it.
        rendered = idaapi.print_tinfo('', 0, 0, 0, newti, utils.string.to(parsedname) if parsedname else utils.string.to(realname), '')

        # Now we need to figure out whether we're adjust the type or explicitly
        # changing it. Afterwards, we should be able to apply it to the function.
        iterable = (guessed[kwd] for kwd in ['guess', 'guessed'] if kwd in guessed)
        flags = [idaapi.TINFO_GUESSED if builtins.next(iterable, False) else idaapi.TINFO_DEFINITE] if any(kwd in guessed for kwd in ['guess', 'guessed']) else []

        # Now we should just be able to apply it to the function... or not.
        result, ok = interface.function.typeinfo(ea), interface.function.apply_typeinfo(ea, newti, *flags)
        if not ok:
            raise E.InvalidTypeOrValueError(u"{:s}({:#x}, {!r}) : Unable to apply the parsed type \"{!s}\" to the specifed {:s} ({:#x}).".format('.'.join([__name__, cls.__name__]), ea, info, utils.string.escape(rendered, '"'), 'address' if rt else 'function', ea))
        return result
    @utils.multicase(func=(idaapi.func_t, types.integer), none=types.none)
    def __new__(cls, func, none):
        '''Remove the type information for the function `func`.'''
        _, ea = interface.addressOfRuntimeOrStatic(func)
        result, ok = interface.function.typeinfo(ea), interface.function.apply_typeinfo(ea, None)
        if not ok:
            raise E.DisassemblerError(u"{:s}({:#x}, {!s}) : Unable to remove the type information from the given function ({:#x}).".format('.'.join([__name__, cls.__name__]), ea, none, ea))
        return result

    @utils.multicase()
    @classmethod
    def flags(cls):
        '''Return the flags for the current function.'''
        return interface.function.flags(ui.current.function())
    @utils.multicase(func=(idaapi.func_t, types.integer))
    @classmethod
    def flags(cls, func):
        '''Return the flags for the function `func`.'''
        fn = interface.function.by(func)
        return interface.function.flags(fn)
    @utils.multicase(func=(idaapi.func_t, types.integer), mask=types.integer)
    @classmethod
    def flags(cls, func, mask):
        '''Return the flags for the function `func` selected with the specified `mask`.'''
        fn = interface.function.by(func, caller='.'.join([__name__, cls.__name__, 'flags']))
        return interface.function.flags(fn, mask)
    @utils.multicase(func=(idaapi.func_t, types.integer), mask=types.integer, integer=(types.bool, types.integer))
    @classmethod
    def flags(cls, func, mask, integer):
        '''Set the flags for the function `func` selected by the specified `mask` to the provided `integer`.'''
        fn = interface.function.by(func, caller='.'.join([__name__, cls.__name__, 'flags']))
        res = interface.function.flags(fn, mask, integer)
        if res is None:
            description = ("{:#x}" if isinstance(func, types.integer) else "{!r}").format(func)
            logging.fatal(u"{:s}.flags({:s}, {:#x}, {!s}) : Unable to change the flags ({:#x}) for function at {:s} to requested value ({:#x}).".format('.'.join([__name__, cls.__name__]), description, mask, value, idaapi.as_uint32(res), description, idaapi.as_uint32(fn.flags)))
        return res

    @utils.multicase()
    @classmethod
    def problem(cls):
        '''Return if the current function has a problem associated with it.'''
        return cls.problem(ui.current.address())
    @utils.multicase(func=(idaapi.func_t, types.integer))
    @classmethod
    def problem(cls, func):
        '''Return if the function `func` has a problem associated with it.'''
        PR_END = getattr(idaapi, 'PR_END', 17)
        iterable = (getattr(idaapi, attribute) for attribute in ['is_problem_present', 'QueueIsPresent'] if hasattr(idaapi, attribute))
        Fproblem = builtins.next(iterable, utils.fconstant(False))

        # Really only PR_BADSTACK is relevant, but we generalize all the problems
        # and by default only ignore ones related to decisions or FLAIR.
        ignored = {getattr(idaapi, name, default) for name, default in [('PR_FINAL', 13), ('PR_COLLISION', 14), ('PR_DECIMP', 15)]}
        problems = {problem for problem in builtins.range(1, PR_END)} - ignored

        # Figure out the function's address, and check if any of the problems apply.
        _, ea = interface.addressOfRuntimeOrStatic(func)
        return any(Fproblem(problem, ea) for problem in problems)
    @utils.multicase(func=(idaapi.func_t, types.integer), problem=types.integer)
    @classmethod
    def problem(cls, func, problem):
        '''Return if the function `func` has the specified `problem` associated with it.'''
        PR_END = getattr(idaapi, 'PR_END', 17)
        iterable = (getattr(idaapi, attribute) for attribute in ['is_problem_present', 'QueueIsPresent'] if hasattr(idaapi, attribute))
        Fproblem = builtins.next(iterable, utils.fconstant(False))

        # Now we can just ask if the specified problem exists for the function.
        _, ea = interface.addressOfRuntimeOrStatic(func)
        return Fproblem(problem, ea)
    has_problem = utils.alias(problem, 'type')

    @utils.multicase()
    @classmethod
    def problems(cls):
        '''Return the problems within the current function as set of integers which correspond to one of the ``idaapi.PR_*`` constants.'''
        return cls.problems(ui.current.function())
    @utils.multicase(func=(idaapi.func_t, types.integer))
    @classmethod
    def problems(cls, func):
        '''Return the problems within the function `func` as set of integers which correspond to one of the ``idaapi.PR_*`` constants.'''
        PR_END = getattr(idaapi, 'PR_END', 17)
        iterable = (getattr(idaapi, attribute) for attribute in ['is_problem_present', 'QueueIsPresent'] if hasattr(idaapi, attribute))
        Fproblem = builtins.next(iterable, utils.fconstant(False))
        _, ea = interface.addressOfRuntimeOrStatic(func)
        return {problem for problem in builtins.range(1, PR_END) if Fproblem(problem, ea)}

    @utils.multicase()
    @classmethod
    def decompiled(cls):
        '''Return if the current function has been decompiled.'''
        return cls.decompiled(ui.current.address())
    @utils.multicase(func=(idaapi.func_t, types.integer))
    @classmethod
    def decompiled(cls, func):
        '''Return if the function `func` has been decompiled.'''
        AFL_HR_DETERMINED = getattr(idaapi, 'AFL_HR_DETERMINED', 0xc0000000)
        _, ea = interface.addressOfRuntimeOrStatic(func)
        return True if interface.node.aflags(ea, AFL_HR_DETERMINED) else False
    is_decompiled = utils.alias(decompiled, 'type')

    @utils.multicase()
    @classmethod
    def frame(cls):
        '''Return if the current function has a frame allocated to it.'''
        return cls.frame(ui.current.function())
    @utils.multicase(func=(idaapi.func_t, types.integer))
    @classmethod
    def frame(cls, func):
        '''Return if the function `func` has a frame allocated to it.'''
        fn = interface.function.by(func, caller='.'.join([__name__, cls.__name__, 'frame']))
        return fn.frame != idaapi.BADADDR
    has_frame = utils.alias(frame, 'type')

    @utils.multicase()
    @classmethod
    def frameptr(cls):
        '''Return if the current function uses a frame pointer (register).'''
        return cls.frameptr(ui.current.function())
    @utils.multicase(func=(idaapi.func_t, types.integer))
    @classmethod
    def frameptr(cls, func):
        '''Return if the function `func` uses a frame pointer (register).'''
        fn = func if isinstance(func, idaapi.func_t) else idaapi.get_func(func)
        return True if fn and interface.function.flags(fn, idaapi.FUNC_FRAME) else False
    has_frameptr = utils.alias(frameptr, 'type')

    @utils.multicase()
    @classmethod
    def name(cls):
        '''Return if the current function has a user-defined name.'''
        return cls.name(ui.current.address())
    @utils.multicase(func=(idaapi.func_t, types.integer))
    @classmethod
    def name(cls, func):
        '''Return if the function `func` has a user-defined name.'''
        _, ea = interface.addressOfRuntimeOrStatic(func)
        return interface.address.flags(ea, idaapi.FF_NAME) == idaapi.FF_NAME
    named = has_name = utils.alias(name, 'type')

    @utils.multicase()
    @classmethod
    def leave(cls):
        '''Return whether the function at the current address returns to its caller.'''
        return cls.leave(ui.current.address())
    @utils.multicase(func=(idaapi.func_t, types.integer))
    @classmethod
    def leave(cls, func):
        '''Return whether the function `func` returns to its caller.'''
        rt, ea = interface.addressOfRuntimeOrStatic(func)
        if rt:
            return False if interface.node.aflags(ea, idaapi.AFL_NORET) else True

        fn = interface.function.by(func)
        if interface.function.flags(fn, idaapi.FUNC_NORET_PENDING) == idaapi.FUNC_NORET_PENDING:
            logging.warning(u"{:s}.leave({:s}) : The analysis for the current function being returned is still pending due to the `{:s}({:#x})` flag being set.".format('.'.join([__name__, cls.__name__]), ea, 'FUNC_NORET_PENDING', idaapi.FUNC_NORET_PENDING))
        return not interface.function.flags(fn, idaapi.FUNC_NORET)
    @utils.multicase(func=(idaapi.func_t, types.integer))
    @classmethod
    def leave(cls, func, boolean):
        '''Update the flags for the function `func` to specify whether it returns to its caller depending on `boolean`.'''
        rt, ea = interface.addressOfRuntimeOrStatic(func)
        if rt:
            result = interface.node.aflags(ea, idaapi.AFL_NORET, 0 if boolean else -1)
        else:
            fn = interface.function.by(func)
            result = interface.function.flags(fn, idaapi.FUNC_NORET, 0 if boolean else -1)
        return False if result else True
    has_return = returns = leaves = utils.alias(leave, 'type')

    @utils.multicase()
    @classmethod
    def library(cls):
        '''Return a boolean describing whether the current function is considered a library function.'''
        return cls.library(ui.current.function())
    @utils.multicase(func=(idaapi.func_t, types.integer))
    @classmethod
    def library(cls, func):
        '''Return a boolean describing whether the function `func` is considered a library function.'''
        fn = func if isinstance(func, idaapi.func_t) else idaapi.get_func(func)
        return True if fn and interface.function.flags(fn, idaapi.FUNC_LIB) else False
    @utils.multicase(func=(idaapi.func_t, types.integer))
    @classmethod
    def library(cls, func, boolean):
        '''Modify the attributes of the function `func` to set it as a library function depending on the value of `boolean`.'''
        fn = interface.function.by(func, caller='.'.join([__name__, cls.__name__, 'library']))
        return interface.function.flags(fn, idaapi.FUNC_LIB, -1 if boolean else 0) == idaapi.FUNC_LIB
    is_library = utils.alias(library, 'type')

    @utils.multicase()
    @classmethod
    def thunk(cls):
        '''Return a boolean describing whether the current function was determined to be a code thunk.'''
        return cls.thunk(ui.current.function())
    @utils.multicase(func=(idaapi.func_t, types.integer))
    @classmethod
    def thunk(cls, func):
        '''Return a boolean describing whether the function `func` was determined to be a code thunk.'''
        fn = func if isinstance(func, idaapi.func_t) else idaapi.get_func(func)
        return True if fn and interface.function.flags(fn, idaapi.FUNC_THUNK) else False
    @utils.multicase(func=(idaapi.func_t, types.integer))
    @classmethod
    def thunk(cls, func, boolean):
        '''Modify the attributes of the function `func` to set it as a code thunk depending on the value of `boolean`.'''
        fn = interface.function.by(func, caller='.'.join([__name__, cls.__name__, 'thunk']))
        return interface.function.flags(fn, idaapi.FUNC_THUNK, -1 if boolean else 0) == idaapi.FUNC_THUNK
    is_thunk = utils.alias(thunk, 'type')

    @utils.multicase()
    @classmethod
    def far(cls):
        '''Return a boolean describing whether the current function is considered a "far" function by IDA or the user.'''
        return cls.far(ui.current.function())
    @utils.multicase(func=(idaapi.func_t, types.integer))
    @classmethod
    def far(cls, func):
        '''Return a boolean describing whether the function `func` is considered a "far" function by IDA or the user.'''
        fn = func if isinstance(func, idaapi.func_t) else idaapi.get_func(func)
        return True if fn and interface.function.flags(fn, idaapi.FUNC_FAR | idaapi.FUNC_USERFAR) else False
    is_far = utils.alias(far, 'type')

    @utils.multicase()
    @classmethod
    def static(cls):
        '''Return a boolean describing whether the current function is defined as a static function.'''
        return cls.static(ui.current.function())
    @utils.multicase(func=(idaapi.func_t, types.integer))
    @classmethod
    def static(cls, func):
        '''Return a boolean describing whether the function `func` is defined as a static function.'''
        FUNC_STATICDEF = idaapi.FUNC_STATICDEF if hasattr(idaapi, 'FUNC_STATICDEF') else idaapi.FUNC_STATIC
        fn = func if isinstance(func, idaapi.func_t) else idaapi.get_func(func)
        return True if fn and interface.function.flags(fn, FUNC_STATICDEF) else False
    @utils.multicase(func=(idaapi.func_t, types.integer))
    @classmethod
    def static(cls, func, boolean):
        '''Modify the attributes of the function `func` to set it as a static function depending on the value of `boolean`.'''
        FUNC_STATICDEF = idaapi.FUNC_STATICDEF if hasattr(idaapi, 'FUNC_STATICDEF') else idaapi.FUNC_STATIC
        fn = interface.function.by(func, caller='.'.join([__name__, cls.__name__, 'static']))
        return interface.function.flags(fn, FUNC_STATICDEF, -1 if boolean else 0) == FUNC_STATICDEF
    is_static = utils.alias(static, 'type')

    @utils.multicase()
    @classmethod
    def hidden(cls):
        '''Return a boolean describing whether the current function is hidden.'''
        return cls.hidden(ui.current.function())
    @utils.multicase(func=(idaapi.func_t, types.integer))
    @classmethod
    def hidden(cls, func):
        '''Return a boolean describing whether the function `func` is hidden.'''
        fn = func if isinstance(func, idaapi.func_t) else idaapi.get_func(func)
        return True if fn and interface.function.flags(fn, idaapi.FUNC_HIDDEN) else False
    @utils.multicase(func=(idaapi.func_t, types.integer))
    @classmethod
    def hidden(cls, func, boolean):
        '''Modify the attributes of the function `func` to set it as a hidden function depending on the value of `boolean`.'''
        fn = interface.function.by(func, caller='.'.join([__name__, cls.__name__, 'hidden']))
        return interface.function.flags(fn, idaapi.FUNC_HIDDEN, -1 if boolean else 0) == idaapi.FUNC_HIDDEN
    is_hidden = hide = utils.alias(hidden, 'type')

    @utils.multicase()
    @classmethod
    def outline(cls):
        '''Return a boolean describing whether the current function is outlined.'''
        return cls.outline(ui.current.function())
    @utils.multicase(func=(idaapi.func_t, types.integer))
    @classmethod
    def outline(cls, func):
        '''Return a boolean describing whether the function `func` is outlined.'''
        FUNC_OUTLINE = getattr(idaapi, 'FUNC_OUTLINE', 0x20000)
        fn = func if isinstance(func, idaapi.func_t) else idaapi.get_func(func)
        return True if fn and interface.function.flags(fn, FUNC_OUTLINE) else False
    @utils.multicase(func=(idaapi.func_t, types.integer))
    @classmethod
    def outline(cls, func, boolean):
        '''Modify the attributes of the function `func` to set it as an outlined function depending on the value of `boolean`.'''
        FUNC_OUTLINE = getattr(idaapi, 'FUNC_OUTLINE', 0x20000)
        fn = interface.function.by(func, caller='.'.join([__name__, cls.__name__, 'outline']))
        return interface.function.flags(fn, FUNC_OUTLINE, -1 if boolean else 0) == idaapi.FUNC_OUTLINE
    is_outline = utils.alias(outline, 'type')

    @utils.multicase()
    @classmethod
    def has(cls):
        '''Return a boolean describing whether the current function has a prototype associated with it.'''
        return cls.has(ui.current.address())
    @utils.multicase(func=(idaapi.func_t, types.integer))
    @classmethod
    def has(cls, func):
        '''Return a boolean describing whether the function `func` has a prototype associated with it.'''
        return interface.function.has_typeinfo(func)
    has_prototype = prototype = has_typeinfo = utils.alias(has, 'type')

    @utils.multicase()
    @classmethod
    def convention(cls):
        '''Return the calling convention of the current function.'''
        # we avoid ui.current.function() so that we can also act on runtime-linked functions.
        return cls.convention(ui.current.address())
    @utils.multicase(convention=(types.string, types.none, types.ellipsis))
    @classmethod
    def convention(cls, convention):
        '''Set the calling convention used by the prototype of the current function to the string specified by `convention`.'''
        return cls.convention(ui.current.address(), convention)
    @utils.multicase(func=(idaapi.func_t, types.integer))
    @classmethod
    def convention(cls, func):
        '''Return the calling convention for the function `func` as an integer that corresponds to one of the ``idaapi.CM_CC_*`` constants.'''
        ti, ftd = interface.tinfo.function_details(func)
        result, spoiled_count = ftd.cc & idaapi.CM_CC_MASK, ftd.cc & ~idaapi.CM_CC_MASK
        return result
    @utils.multicase(type=idaapi.tinfo_t)
    @classmethod
    def convention(cls, type):
        '''Return the calling convention from the prototype specified by `type` as an integer that corresponds to one of the ``idaapi.CM_CC_*`` constants.'''
        tinfo = type
        while tinfo.is_ptr():
            tinfo = tinfo.get_pointed_object()

        # Verify that it's actually a function prototype...
        if not any([tinfo.is_func(), tinfo.is_funcptr()]):
            raise E.InvalidTypeOrValueError(u"{:s}.convention({!r}) : The resolved type information \"{:s}\" is not a function and does not contain any arguments.".format('.'.join([__name__, cls.__name__]), "{!s}".format(type), internal.utils.string.escape("{!s}".format(tinfo), '"')))

        # ...and make sure it has details that we can use.
        elif not tinfo.has_details():
            raise E.MissingTypeOrAttribute(u"{:s}.convention({!r}) : The resolved type information \"{:s}\" does not contain any details.".format('.'.join([__name__, cls.__name__]), "{!s}".format(type), internal.utils.string.escape("{!s}".format(tinfo), '"')))

        # Now we can just get the function details from the type...
        ftd = idaapi.func_type_data_t()
        ok = tinfo.get_func_details(ftd) or tinfo.get_func_details(ftd, idaapi.GTD_NO_ARGLOCS)
        if not ok:
            raise E.DisassemblerError(u"{:s}.convention({!r}) : Unable to retrieve the details from the specified type information \"{:s}\".".format('.'.join([__name__, cls.__name__]), "{!s}".format(type), internal.utils.string.escape("{!s}".format(tinfo), '"')))

        # ...and then return the calling convention from it.
        result, spoiled_count = ftd.cc & idaapi.CM_CC_MASK, ftd.cc & ~idaapi.CM_CC_MASK
        return result
    @utils.multicase(func=(idaapi.func_t, types.integer), convention=(types.string, types.none, types.ellipsis))
    @classmethod
    def convention(cls, func, convention):
        '''Set the calling convention used by the prototype of the function `func` to the string specified by `convention`.'''
        cc = internal.declaration.convention.get(convention)
        return cls.convention(func, cc)
    @utils.multicase(func=(idaapi.func_t, types.integer), convention=types.integer)
    @classmethod
    def convention(cls, func, convention):
        '''Set the calling convention used by the prototype of the function `func` to the specified `convention`.'''
        _, ea = interface.addressOfRuntimeOrStatic(func)
        updater = interface.tinfo.update_function_details(ea)

        # Grab the type and function details from our updater coroutine.
        ti, ftd = builtins.next(updater)

        # Update the calling convention whilst preserving the spoiled count.
        # If it has extra bits that were set, then we need to warn the user
        # about it, and then we can send it back to the updater.
        if convention & ~idaapi.CM_CC_MASK:
            logging.warning(u"{:s}.convention({:#x}, {:#x}) : The convention that was provided ({:#x}) contains extra bits ({:#x}) that will be masked ({:#x}) out.".format('.'.join([__name__, cls.__name__]), ea, convention, convention, convention & ~idaapi.CM_CC_MASK, idaapi.CM_CC_MASK))
        result, ftd.cc = ftd.cc, (ftd.cc & ~idaapi.CM_CC_MASK) | (convention & idaapi.CM_CC_MASK)

        # Now we can send the updater our modified ftd, close it, and then
        # return the value that was set prevously.
        updater.send(ftd), updater.close()
        return result & idaapi.CM_CC_MASK
    @utils.multicase(type=idaapi.tinfo_t, convention=(types.integer, types.string, types.none, types.ellipsis))
    @classmethod
    def convention(cls, type, convention):
        '''Set the calling convention of the prototype in `type` to the specified `convention`.'''
        tinfo, cc = type, convention if isinstance(convention, types.integer) else internal.declaration.convention.get(convention)

        # Create an updater for the specified type, and then
        # grab whatever type details that it yields back to us.
        updater = interface.tinfo.update_prototype_details(tinfo)
        prototype, ftd = builtins.next(updater)

        # Now we can just exchange the calling convention from the details.
        res, ftd.cc = ftd.cc, (ftd.cc & ~idaapi.CM_CC_MASK) | (cc & idaapi.CM_CC_MASK)

        # Then we send it back to the updater, and return whatever we received.
        try:
            newinfo, _ = updater.send(ftd)
        except E.DisassemblerError:
            raise E.DisassemblerError(u"{:s}.convention({!r}, {:#x}) : Unable to modify the calling convention ({:#x}) for the specified type \"{:s}\".".format('.'.join([__name__, cls.__name__]), "{!s}".format(type), cc, prototype))
        finally:
            updater.close()
        return newinfo
    cc = utils.alias(convention, 'type')

    @utils.multicase()
    @classmethod
    def spoiled(cls):
        '''Return a list of the spoiled registers from the prototype of the current function.'''
        return cls.spoiled(ui.current.address())
    @utils.multicase(registers=(types.unordered, types.none))
    @classmethod
    def spoiled(cls, registers):
        '''Update the prototype of the current function by applying or removing the specified spoiled `registers`.'''
        return cls.spoiled(ui.current.address(), registers)
    @utils.multicase(func=(idaapi.func_t, types.integer))
    @classmethod
    def spoiled(cls, func):
        '''Return a list of the spoiled registers from the prototype of the function `func`.'''
        tinfo = interface.function.typeinfo(func)
        if tinfo is None:
            _, ea = interface.addressOfRuntimeOrStatic(func)
            raise E.DisassemblerError(u"{:s}.spoiled({:#x}) : Unable to get the prototype for the specified function ({:#x}).".format('.'.join([__name__, cls.__name__]), ea, ea))
        return [register for register in interface.tinfo.function_spoiled(tinfo)]
    @utils.multicase(func=(idaapi.func_t, types.integer), registers=types.unordered)
    @classmethod
    def spoiled(cls, func, registers):
        '''Update the prototype for the function `func` with the specified spoiled `registers`.'''
        tinfo = interface.function.typeinfo(func)
        if tinfo is None:
            _, ea = interface.addressOfRuntimeOrStatic(func)
            raise E.DisassemblerError(u"{:s}.spoiled({:#x}, {!r}) : Unable to get the prototype for the specified function ({:#x}).".format('.'.join([__name__, cls.__name__]), ea, registers, ea))

        # Make a copy of the old type and create a new type with the specified registers.
        old, new = tinfo, interface.tinfo.update_function_spoiled(tinfo, registers)
        if not interface.function.apply_typeinfo(func, new):
            _, ea = interface.addressOfRuntimeOrStatic(func)
            raise E.InvalidTypeOrValueError(u"{:s}.spoiled({:#x}, {!r}) : Unable to update the prototype for the specified function ({:#x}) with the new type \"{:s}\".".format('.'.join([__name__, cls.__name__]), ea, registers, ea, utils.string.escape(new, '"')))
        return [register for register in interface.tinfo.function_spoiled(old)]
    @utils.multicase(func=(idaapi.func_t, types.integer), none=types.none)
    @classmethod
    def spoiled(cls, func, none):
        '''Remove the spoiled registers from the prototype of the function `func`.'''
        tinfo = interface.function.typeinfo(func)
        if tinfo is None:
            _, ea = interface.addressOfRuntimeOrStatic(func)
            raise E.DisassemblerError(u"{:s}.spoiled({:#x}, {!s}) : Unable to get the prototype for the specified function ({:#x}).".format('.'.join([__name__, cls.__name__]), ea, none, ea))

        # Remove the spoiled registers from the new type, and apply them to
        # the requested function. Afterwards, return whatever was removed.
        old, new = tinfo, interface.tinfo.update_function_spoiled(tinfo, none)
        if not interface.function.apply_typeinfo(func, new):
            _, ea = interface.addressOfRuntimeOrStatic(func)
            raise E.InvalidTypeOrValueError(u"{:s}.spoiled({:#x}, {!s}) : Unable to update the prototype for the specified function ({:#x}) with the new type \"{:s}\".".format('.'.join([__name__, cls.__name__]), ea, none, ea, utils.string.escape(new, '"')))
        return [register for register in interface.tinfo.function_spoiled(old)]
    @utils.multicase(type=(internal.types.string, idaapi.tinfo_t))
    @classmethod
    def spoiled(cls, type):
        '''Return a list of the spoiled registers from the prototype specified by `type`.'''
        tinfo = type if isinstance(type, idaapi.tinfo_t) else interface.tinfo.parse(None, type, idaapi.PT_SIL)
        if tinfo is None:
            raise E.InvalidTypeOrValueError(u"{:s}.spoiled({!r}) : Unable to parse the specified string \"{:s}\" into a type.".format('.'.join([__name__, cls.__name__]), "{!s}".format(type), utils.string.escape("{!s}".format(type), '"')))
        return [register for register in interface.tinfo.function_spoiled(tinfo)]
    @utils.multicase(type=(internal.types.string, idaapi.tinfo_t), none=types.none)
    @classmethod
    def spoiled(cls, type, none):
        '''Remove the spoiled registers from the prototype specified by `type`.'''
        tinfo = type if isinstance(type, idaapi.tinfo_t) else interface.tinfo.parse(None, type, idaapi.PT_SIL)
        if tinfo is None:
            raise E.InvalidTypeOrValueError(u"{:s}.spoiled({!r}, {!s}) : Unable to parse the specified string \"{:s}\" into a type.".format('.'.join([__name__, cls.__name__]), "{!s}".format(type), none, utils.string.escape("{!s}".format(type), '"')))
        return interface.tinfo.update_function_spoiled(tinfo, none)
    @utils.multicase(type=(internal.types.string, idaapi.tinfo_t), registers=types.unordered)
    @classmethod
    def spoiled(cls, type, registers):
        '''Update the prototype specified by `type` with the given spoiled `registers`.'''
        tinfo = type if isinstance(type, idaapi.tinfo_t) else interface.tinfo.parse(None, type, idaapi.PT_SIL)
        if tinfo is None:
            raise E.InvalidTypeOrValueError(u"{:s}.spoiled({!r}, {!r}) : Unable to parse the specified string \"{:s}\" into a type.".format('.'.join([__name__, cls.__name__]), "{!s}".format(type), registers, utils.string.escape("{!s}".format(type), '"')))
        listable = [item for item in registers]
        return interface.tinfo.update_function_spoiled(tinfo, listable)
    spoils = utils.alias(spoiled, 'type')

    class result(object):
        """
        This namespace allows one to interact with the result as defined
        within a function prototype. This allows one to fetch or modify
        the type information that is returned by a function.

        Some ways to utilize this namespace can be::

            > print( function.type.result() )
            > print( function.type.result.location() )

        """
        @utils.multicase()
        def __new__(cls):
            '''Return the type of the result from the prototype of the current function.'''
            # we avoid ui.current.function() so that we can also act on function pointers.
            return cls(ui.current.address())
        @utils.multicase(info=(idaapi.tinfo_t, types.string))
        def __new__(cls, info):
            '''Apply the type specified in `info` to the result of the prototype from the current function.'''
            if isinstance(info, idaapi.tinfo_t) and not info.is_ptr() and info.is_func():
                return info.get_rettype()
            return cls(ui.current.address(), info)
        @utils.multicase(func=(idaapi.func_t, types.integer))
        def __new__(cls, func):
            '''Return the type of the result from the prototype of the function `func`.'''
            tinfo, ftd = interface.tinfo.function_details(func)
            return interface.tinfo.copy(ftd.rettype)
        @utils.multicase(func=(idaapi.func_t, types.integer), string=types.string)
        @utils.string.decorate_arguments('string')
        def __new__(cls, func, string):
            '''Apply the type specified as `string` to the result of the prototype for the function `func`.'''
            tinfo = interface.tinfo.parse(None, string, idaapi.PT_SIL)
            if tinfo is None:
                raise E.InvalidTypeOrValueError(u"{:s}({!r}, {!r}) : Unable to parse the provided type information ({!r}).".format('.'.join([__name__, 'type', cls.__name__]), func, string, string))
            return cls(func, tinfo)
        @utils.multicase(func=(idaapi.func_t, types.integer), info=idaapi.tinfo_t)
        def __new__(cls, func, info):
            '''Apply the type specified in `info` to the result of the prototype for the function `func`.'''
            updater = interface.tinfo.update_function_details(func)

            # Now we can grab the details out of the updater.
            _, ftd = builtins.next(updater)

            # From this, we'll trade the return type with the one the user gave us,
            # and then send it back to the updater to write it to the address.
            result, ftd.rettype = interface.tinfo.copy(ftd.rettype), info
            updater.send(ftd), updater.close()

            # That was it and we only need to return the previous value.
            return result
        @utils.multicase(type=idaapi.tinfo_t, info=(idaapi.tinfo_t, types.string))
        def __new__(cls, type, info):
            '''Apply the type in `info` to the result for the prototype specified by `type`.'''
            tinfo = info if isinstance(info, idaapi.tinfo_t) else interface.tinfo.parse(None, info, idaapi.PT_SIL)
            if tinfo is None:
                raise E.InvalidTypeOrValueError(u"{:s}({!r}, {!r}) : Unable to parse the provided result ({!r}) into a valid type.".format('.'.join([__name__, 'type', cls.__name__]), type, info, info))

            # Now we can create an updater for the prototype, and
            # then grab whatever details that it gives back to us.
            updater = interface.tinfo.update_prototype_details(type)
            prototype, ftd = builtins.next(updater)

            # All we need to do is to assign whatever the user gave us to the return type.
            result, ftd.rettype = interface.tinfo.copy(ftd.rettype), tinfo

            # Then, we can send the details back to the updater to get our new type.
            try:
                newinfo, _ = updater.send(ftd)
            except E.DisassemblerError:
                raise E.DisassemblerError(u"{:s}({!r}, {!r}) : Unable to modify the result for the specified prototype \"{:s}\".".format('.'.join([__name__, 'type', cls.__name__]), "{!s}".format(type), "{!s}".format(info), prototype))
            finally:
                updater.close()
            return newinfo

        @utils.multicase()
        @classmethod
        def storage(cls):
            '''Return the storage location of the result from the prototype of the current function.'''
            return cls.storage(ui.current.address())
        @utils.multicase(func=(idaapi.func_t, types.integer))
        @classmethod
        def storage(cls, func):
            '''Return the storage location of the result from the prototype of the function `func`.'''
            tinfo, ftd = interface.tinfo.function_details(func)

            # Rip the result type and raw location out of the the function details.
            tinfo, location = ftd.rettype, ftd.retloc
            locinfo = interface.tinfo.location_raw(location)

            # Convert the raw location to a real one, and then figure out how to return it.
            result = interface.tinfo.location(tinfo.get_size(), instruction.architecture, *locinfo)
            if isinstance(result, types.tuple) and any(isinstance(item, interface.register_t) for item in result):
                reg, offset = result
                return result if offset else reg
            return result
        @utils.multicase(type=(internal.types.string, idaapi.tinfo_t))
        @classmethod
        def storage(cls, type):
            '''Return the storage location of the result from the prototype specified by `type`.'''
            tinfo = type if isinstance(type, idaapi.tinfo_t) else interface.tinfo.parse(None, type, idaapi.PT_SIL)
            if tinfo is None:
                raise E.InvalidTypeOrValueError(u"{:s}.storage({!r}) : Unable to parse the specified string \"{:s}\" into a type.".format('.'.join([__name__, 'type', cls.__name__]), "{!s}".format(type), utils.string.escape("{!s}".format(type), '"')))
            result_and_parameters = interface.tinfo.function(tinfo)
            [(name, type, storage)] = result_and_parameters[:1]
            return storage

    class argument(object):
        """
        This namespace allows one to interact with individual arguments
        within a function prototype. This allows one to rename or modify
        the type information for a particular argument within its definition.

        This namespace is aliased as ``function.type.arg`` and ``function.type.parameter``.

        Some simple ways of fetching or modifying the type of the first parameter
        in a function:

            > print( function.argument(0) )
            > print( function.argument.name(1) )
            > oldtype = function.argument(0, 'void*')
            > oldname = function.argument.name(1)
            > storage = function.argument.storage(2)
            > index = function.argument.remove(3)

        """

        @utils.multicase(index=types.integer)
        def __new__(cls, index):
            '''Return the type of the parameter at the given `index` from the prototype of the current function.'''
            return cls(ui.current.address(), index)
        @utils.multicase(index=types.integer, info=(types.string, idaapi.tinfo_t))
        def __new__(cls, index, info):
            '''Apply the type in `info` to the parameter at the given `index` from the prototype of the current function.'''
            return cls(ui.current.address(), index, info)
        @utils.multicase(func=(idaapi.func_t, types.integer), index=types.integer)
        def __new__(cls, func, index):
            '''Return the type of the parameter at the given `index` of the prototype from the function `func`.'''
            _, ea = interface.addressOfRuntimeOrStatic(func)

            # Use the address and tinfo to grab the details containing our arguments,
            # and then check that the index is actually within its boundaries.
            tinfo, ftd = interface.tinfo.function_details(func)
            if not (0 <= index < ftd.size()):
                raise E.IndexOutOfBoundsError(u"{:s}({:#x}, {:d}) : The provided index ({:d}) is not within the range of the number of arguments ({:d}) for the specified function ({:#x}).".format('.'.join([__name__, 'type', cls.__name__]), ea, index, index, ftd.size(), ea))

            # Now we can grab the argument using the index we were given and return its type.
            result = ftd[index]
            return interface.tinfo.copy(result.type)
        @utils.multicase(type=(internal.types.string, idaapi.tinfo_t), index=types.integer)
        def __new__(cls, type, index):
            '''Return the type of the parameter at the given `index` of the prototype specified by `type`.'''
            tinfo = type if isinstance(type, idaapi.tinfo_t) else interface.tinfo.parse(None, type, idaapi.PT_SIL)
            if tinfo is None:
                raise E.InvalidTypeOrValueError(u"{:s}({!r}, {:d}) : Unable to parse the specified string \"{:s}\" into a type.".format('.'.join([__name__, 'type', cls.__name__]), "{!s}".format(type), index, utils.string.escape("{!s}".format(type), '"')))
            result = tinfo.get_nth_arg(index)
            return interface.tinfo.copy(result)
        @utils.multicase(func=(idaapi.func_t, types.integer), index=types.integer, info=idaapi.tinfo_t)
        def __new__(cls, func, index, info):
            '''Apply the type in `info` to the parameter at the given `index` of the prototype from the function `func`.'''
            _, ea = internal.interface.addressOfRuntimeOrStatic(func)
            updater = interface.tinfo.update_function_details(func)

            # Grab the details out of the updater so that we can check the index.
            ti, ftd = builtins.next(updater)
            if not (0 <= index < ftd.size()):
                raise E.IndexOutOfBoundsError(u"{:s}({:#x}, {:d}, {!r}) : The provided index ({:d}) is not within the range of the number of arguments ({:d}) for the specified function ({:#x}).".format('.'.join([__name__, 'type', cls.__name__]), ea, index, "{!s}".format(info), index, ftd.size(), ea))

            # Now we can just trade their type with the argument at the given index.
            argument = ftd[index]
            result, argument.type = interface.tinfo.copy(argument.type), info

            # Then we can send it back to our updater, and return the previous value.
            updater.send(ftd), updater.close()
            return result
        @utils.multicase(func=(idaapi.func_t, types.integer), index=types.integer, string=types.string)
        @utils.string.decorate_arguments('string')
        def __new__(cls, func, index, string):
            '''Apply the type specified as `string` to the parameter at the given `index` of the prototype from the function `func`.'''
            tinfo = interface.tinfo.parse(None, string, idaapi.PT_SIL)
            if tinfo is None:
                raise E.InvalidTypeOrValueError(u"{:s}({!r}, {:d}, {!r}) : Unable to parse the provided type information ({!r}).".format('.'.join([__name__, 'type', cls.__name__]), func, index, string, string))
            return cls(func, index, tinfo)
        @utils.multicase(type=idaapi.tinfo_t, index=types.integer, info=(idaapi.tinfo_t, types.string))
        def __new__(cls, type, index, info):
            '''Apply the type in `info` to the parameter at the given `index` of the prototype specified by `type`.'''
            tinfo = info if isinstance(info, idaapi.tinfo_t) else interface.tinfo.parse(None, info, idaapi.PT_SIL)
            if tinfo is None:
                raise E.InvalidTypeOrValueError(u"{:s}({!r}, {:d}, {!r}) : Unable to parse the provided argument type into a valid type.".format('.'.join([__name__, 'type', cls.__name__]), "{!s}".format(type), index, "{!s}".format(info)))

            # Start by creating an updater for the prototype, and grab what it gives back to us.
            updater = interface.tinfo.update_prototype_details(type)
            prototype, ftd = builtins.next(updater)

            # Verify that the index we were given is actually valid.
            if not (0 <= index < ftd.size()):
                raise E.IndexOutOfBoundsError(u"{:s}({!r}, {:d}, {!r}) : The provided index ({:d}) is not within the range of the number of arguments ({:d}) for the specified prototype.".format('.'.join([__name__, 'type', cls.__name__]), "{!s}".format(type), index, "{!s}".format(info), index, ftd.size()))

            # Now we can just trade their type with the argument.
            argument = ftd[index]
            result, argument.type = interface.tinfo.copy(argument.type), tinfo

            # Then send the details back to the updater to get the new type to return.
            try:
                newinfo, _ = updater.send(ftd)
            except E.DisassemblerError:
                raise E.DisassemblerError(u"{:s}({!r}, {:d}, {!r}) : Unable to modify the result for the specified prototype \"{:s}\".".format('.'.join([__name__, 'type', cls.__name__]), "{!s}".format(type), index, "{!s}".format(info), utils.string.escape("{!s}".format(prototype), '"')))
            finally:
                updater.close()
            return newinfo

        @utils.multicase(index=types.integer)
        @classmethod
        def name(cls, index):
            '''Return the name of the parameter at the given `index` of the prototype from the current function.'''
            return cls.name(ui.current.address(), index)
        @utils.multicase(index=types.integer, none=types.none)
        @classmethod
        def name(cls, index, none):
            '''Remove the name from the parameter at the given `index` of the prototype from the current function.'''
            return cls.name(ui.current.address(), index, none)
        @utils.multicase(index=types.integer, string=types.string)
        @classmethod
        def name(cls, index, string, *suffix):
            '''Rename the parameter at the given `index` of the prototype from the current function to `string`.'''
            return cls.name(ui.current.address(), index, string, *suffix)
        @utils.multicase(func=(idaapi.func_t, types.integer), index=types.integer)
        @classmethod
        def name(cls, func, index):
            '''Return the name of the parameter at the given `index` of the prototype from the function `func`.'''
            _, ea = internal.interface.addressOfRuntimeOrStatic(func)

            # Use the address and type to get the function details, and then check that
            # the user's index is within their boundaries to access the argument name.
            tinfo, ftd = interface.tinfo.function_details(func)
            if not (0 <= index < ftd.size()):
                raise E.IndexOutOfBoundsError(u"{:s}.name({:#x}, {:d}) : The provided index ({:d}) is not within the range of the number of arguments ({:d}) for the specified function ({:#x}).".format('.'.join([__name__, 'type', cls.__name__]), ea, index, index, ftd.size(), ea))

            # Now we can grab the argument using the index we were given and return its name.
            result = ftd[index]
            return utils.string.of(result.name) or None
        @utils.multicase(type=idaapi.tinfo_t, index=types.integer)
        @classmethod
        def name(cls, type, index):
            '''Return the name of the parameter at the given `index` of the prototype specified by `type`.'''
            tinfo, ftd = interface.tinfo.prototype_details(type)
            if not (0 <= index < ftd.size()):
                raise E.IndexOutOfBoundsError(u"{:s}.name({!r}, {:d}) : The provided index ({:d}) is not within the range of the number of arguments ({:d}) for the specified prototype.".format('.'.join([__name__, 'type', cls.__name__]), "{!s}".format(type), index, index, ftd.size()))
            result = ftd[index]
            return utils.string.of(result.name) or None
        @utils.multicase(func=(idaapi.func_t, types.integer, idaapi.tinfo_t), index=types.integer, none=types.none)
        @classmethod
        def name(cls, func, index, none):
            '''Remove the name from the parameter at the given `index` of the prototype from the function `func`.'''
            return cls.name(func, index, '')
        @utils.multicase(func=(idaapi.func_t, types.integer), index=types.integer, string=types.string)
        @classmethod
        @utils.string.decorate_arguments('string', 'suffix')
        def name(cls, func, index, string, *suffix):
            '''Rename the parameter at the given `index` of the prototype from the function `func` to `string`.'''
            _, ea = interface.addressOfRuntimeOrStatic(func)
            name = interface.tuplename(*itertools.chain([string], suffix))
            updater = interface.tinfo.update_function_details(func)

            # Now we can just grab the type and func_type_data_t from the updater
            # and check that the requested argument index is within its bounds.
            tinfo, ftd = builtins.next(updater)
            if not (0 <= index < ftd.size()):
                raise E.IndexOutOfBoundsError(u"{:s}.name({:#x}, {:d}, {!s}) : The provided index ({:d}) is not within the range of the number of arguments ({:d}) for the specified function ({:#x}).".format('.'.join([__name__, 'type', cls.__name__]), ea, index, utils.string.repr(name), index, ftd.size(), ea))

            # Only thing left to do is to trade the name the user gave us with
            # whatever was stored at the parameter index they specified.
            argument = ftd[index]
            result, argument.name = argument.name, utils.string.to(name)

            # Now we can send the whole thing back to the updater, close it,
            # and then return the previous result that was assigned.
            updater.send(ftd), updater.close()
            return result or None
        @utils.multicase(type=idaapi.tinfo_t, index=types.integer, string=types.string)
        @classmethod
        @utils.string.decorate_arguments('string', 'suffix')
        def name(cls, type, index, string, *suffix):
            '''Rename the parameter at the given `index` of the prototype specified by `type` to `string`.'''
            name = interface.tuplename(*itertools.chain([string], suffix))

            # Create an updater for the prototype, and
            # grab whatever it wants to give back to us.
            updater = interface.tinfo.update_prototype_details(type)
            prototype, ftd = builtins.next(updater)

            # Before doing anything, verify the requested index is within bounds.
            if not (0 <= index < ftd.size()):
                raise E.IndexOutOfBoundsError(u"{:s}.name({!r}, {:d}, {!s}) : The provided index ({:d}) is not within the range of the number of arguments ({:d}) for the specified prototype.".format('.'.join([__name__, 'type', cls.__name__]), "{!s}".format(type), index, utils.string.repr(name), index, ftd.size()))

            # Now we can exchange the name with the one the user gave us.
            argument = ftd[index]
            result, argument.name = argument.name, utils.string.to(name)

            # Then send the details back to the updater to get the new type to return.
            try:
                newinfo, _ = updater.send(ftd)
            except E.DisassemblerError:
                raise E.DisassemblerError(u"{:s}({!r}, {:d}, {!s}) : Unable to modify the name of the argument ({:d}) for the specified prototype \"{:s}\".".format('.'.join([__name__, 'type', cls.__name__]), "{!s}".format(type), index, utils.string.repr(name), utils.string.escape("{!s}".format(prototype), '"')))
            finally:
                updater.close()
            return newinfo

        @utils.multicase(index=types.integer)
        @classmethod
        def storage(cls, index):
            '''Return the storage location of the parameter at the given `index` of the prototype from the current function.'''
            return cls.storage(ui.current.address(), index)
        @utils.multicase(func=(idaapi.func_t, types.integer), index=types.integer)
        @classmethod
        def storage(cls, func, index):
            '''Return the storage location of the parameter at the given `index` of the prototype from the function `func`.'''
            tinfo = interface.function.typeinfo(func)
            if tinfo is None:
                _, ea = interface.addressOfRuntimeOrStatic(func)
                raise E.DisassemblerError(u"{:s}.storage({:#x}, {:d}) : Unable to get the prototype for the specified function ({:#x}).".format('.'.join([__name__, 'type', cls.__name__]), ea, index, ea))

            # As always, check our bounds and raise an exception...cleanly.
            locations = [item for _, _, item in interface.tinfo.function(tinfo)[1:]]
            if not (0 <= index < len(locations)):
                _, ea = internal.interface.addressOfRuntimeOrStatic(func)
                raise E.IndexOutOfBoundsError(u"{:s}.storage({:#x}, {:d}) : The provided index ({:d}) is not within the range of the number of arguments ({:d}) for the specified function ({:#x}).".format('.'.join([__name__, 'type', cls.__name__]), ea, index, index, len(locations), ea))
            location = locations[index]

            # Otherwise, this might be a tuple and we return the whole thing
            # unless its a (register, offset). If it is, then check that it's
            # a zero-offset because then we can return just the register.
            if isinstance(location, types.tuple):
                reg, off = location
                if isinstance(off, types.integer) and off == 0:
                    return reg
                return location
            return location
        @utils.multicase(type=(internal.types.string, idaapi.tinfo_t), index=types.integer)
        @classmethod
        def storage(cls, type, index):
            '''Return the storage location of the parameter at the given `index` of the prototype specified by `type`.'''
            tinfo = type if isinstance(type, idaapi.tinfo_t) else interface.tinfo.parse(None, type, idaapi.PT_SIL)
            if tinfo is None:
                raise E.InvalidTypeOrValueError(u"{:s}.storage({!r}, {:d}) : Unable to parse the specified string \"{:s}\" into a type.".format('.'.join([__name__, 'type', cls.__name__]), "{!s}".format(type), index, utils.string.escape("{!s}".format(type), '"')))

            # Check the index against the number of available parameters.
            locations = [item for _, _, item in interface.tinfo.function(tinfo)[1:]]
            if not (0 <= index < len(locations)):
                raise E.IndexOutOfBoundsError(u"{:s}.storage({!r}, {:d}) : The provided index ({:d}) is not within the range of the number of arguments ({:d}) for the specified prototype.".format('.'.join([__name__, 'type', cls.__name__]), "{!s}".format(type), index, index, len(locations)))
            location = locations[index]

            # Otherwise, this might be a tuple and we return the whole thing
            # unless its a (register, offset). If it is, then check that it's
            # a zero-offset because then we can return just the register.
            if isinstance(location, types.tuple):
                reg, off = location
                if isinstance(off, types.integer) and off == 0:
                    return reg
                return location
            return location

        @utils.multicase(index=types.integer)
        @classmethod
        def remove(cls, index):
            '''Remove the parameter at the given `index` from the prototype of the current function.'''
            return cls.remove(ui.current.address(), index)
        @utils.multicase(func=(idaapi.func_t, types.integer), index=types.integer)
        @classmethod
        def remove(cls, func, index):
            '''Remove the parameter at the specified `index` from the prototype of the function `func`.'''
            updater = interface.tinfo.update_function_details(func)

            # Grab the type and the details and verify the index is valid before
            # collecting into a list that we'll use for modifying things.
            ti, ftd = builtins.next(updater)
            if not (0 <= index < ftd.size()):
                _, ea = internal.interface.addressOfRuntimeOrStatic(func)
                raise E.IndexOutOfBoundsError(u"{:s}.remove({:#x}, {:d}) : The provided index ({:d}) is not within the range of the number of arguments ({:d}) for the specified function ({:#x}).".format('.'.join([__name__, 'type', cls.__name__]), ea, index, index, ftd.size(), ea))
            items = [ftd[idx] for idx in builtins.range(ftd.size())]

            # Now we can safely modify our list, and pop out the funcarg_t from it.
            farg = items.pop(index)
            name, result, location, comment = utils.string.of(farg.name), interface.tinfo.copy(farg.type), farg.argloc, farg.cmt

            # Instead of recreating the func_type_data_t, we'll reassign the
            # references back in, and then resize it afterwards.
            for idx, item in enumerate(items):
                ftd[idx] = item
            ftd.resize(len(items))

            # At this point we shouldn't have any references to anything that we
            # modified, and can send it back to update the prototype correctly.
            updater.send(ftd), updater.close()
            return result
        @utils.multicase(type=idaapi.tinfo_t, index=types.integer)
        @classmethod
        def remove(cls, type, index):
            '''Remove the parameter at the given `index` from the prototype specified by `type`.'''
            updater = interface.tinfo.update_prototype_details(type)

            # Grab the prototype and details so that we can verify the
            # index is valid before processing the list of arguments.
            prototype, ftd = builtins.next(updater)
            if not (0 <= index < ftd.size()):
                _, ea = internal.interface.addressOfRuntimeOrStatic(func)
                raise E.IndexOutOfBoundsError(u"{:s}.remove({!r}, {:d}) : The provided index ({:d}) is not within the range of the number of arguments ({:d}) for the specified prototype.".format('.'.join([__name__, 'type', cls.__name__]), "{!s}".format(type), index, index, ftd.size()))

            # Collect all the arguments into a list so that we can
            # safely modify it before sending it back to the updater.
            items = [ftd[idx] for idx in builtins.range(ftd.size())]
            farg = items.pop(index)

            # To avoid reinstantiating the function details, we'll just
            # reassign the new items back in. Afterwards, we'll shrink
            # the details to accommodate the removal of an element.
            for idx, item in enumerate(items):
                ftd[idx] = item
            ftd.resize(len(items))

            # We're done. We just need to send the details back to get our result.
            try:
                newinfo, _ = updater.send(ftd)
            except E.DisassemblerError:
                raise E.DisassemblerError(u"{:s}.remove({!r}, {:d}) : Unable to remove the argument at index {:d} of the specified prototype \"{:s}\".".format('.'.join([__name__, 'type', cls.__name__]), "{!s}".format(type), index, index, utils.string.escape("{!s}".format(prototype), '"')))
            finally:
                updater.close()
            return newinfo
        pop = utils.alias(remove, 'type.argument')

        @utils.multicase(index=types.integer)
        @classmethod
        def location(cls, index):
            '''Return the address of the parameter at `index` that is passed to the function referenced at the current address.'''
            return cls.location(ui.current.address(), index)
        @utils.multicase(ea=types.integer, index=types.integer)
        @classmethod
        def location(cls, ea, index):
            '''Return the address of the parameter at `index` that is passed to the function referenced at the address `ea`.'''
            items = interface.instruction.arguments(ea)
            if 0 <= index < len(parameters):
                return parameters[index]
            raise E.IndexOutOfBoundsError(u"{:s}.location({:#x}, {:d}) : Unable to fetch the address of the specified parameter ({:d}) from the function call at address {:#x} due to only {:d} parameter{:s} being available.".format('.'.join([__name__, 'type', cls.__name__]), ea, index, index, ea, len(parameters), '' if len(parameters) == 1 else 's'))

        @utils.multicase(index=types.integer)
        @classmethod
        def unused(cls, index):
            '''Return whether the parameter at the specified `index` of the prototype from the current function is marked as unused.'''
            return cls.unused(ui.current.address(), index)
        @utils.multicase(func=(idaapi.func_t, types.integer), index=types.integer)
        @classmethod
        def unused(cls, func, index):
            '''Return whether the parameter at the specified `index` of the prototype from the function ``func`` is marked as unused.'''
            _, ea = interface.addressOfRuntimeOrStatic(func)

            # Grab the prototype and details from the specified function.
            tinfo, ftd = interface.tinfo.function_details(ea)
            if not (0 <= index < ftd.size()):
                raise E.IndexOutOfBoundsError(u"{:s}.unused({:#x}, {:d}) : The provided index ({:d}) is not within the range of the number of arguments ({:d}) for the specified function ({:#x}).".format('.'.join([__name__, 'type', cls.__name__]), ea, index, index, ftd.size(), ea))

            # Now we can grab the argument using the index we were given and return its name.
            result, FAI_UNUSED = ftd[index], getattr(idaapi, 'FAI_UNUSED', 0x10)
            return True if result.flags & FAI_UNUSED else False
        @utils.multicase(type=idaapi.tinfo_t, index=types.integer)
        @classmethod
        def unused(cls, type, index):
            '''Return whether the parameter at the given `index` of the prototype specified by ``type`` is marked as unused.'''
            prototype, ftd = interface.tinfo.prototype_details(type)
            if not (0 <= index < ftd.size()):
                raise E.IndexOutOfBoundsError(u"{:s}.unused({!r}, {:d}) : The provided index ({:d}) is not within the range of the number of arguments ({:d}) for the specified prototype.".format('.'.join([__name__, 'type', cls.__name__]), "{!s}".format(type), index, index, ftd.size()))
            result, FAI_UNUSED = ftd[index], getattr(idaapi, 'FAI_UNUSED', 0x10)
            return True if result.flags & FAI_UNUSED else False
        @utils.multicase(func=(idaapi.func_t, types.integer), index=types.integer)
        @classmethod
        def unused(cls, func, index, boolean):
            '''Set the unused attribute of the parameter at the specified `index` from the prototype of the function `func` to `boolean`.'''
            updater = interface.tinfo.update_function_details(func)

            # Grab the function type and its details that we can modify it.
            tinfo, ftd = builtins.next(updater)
            if not (0 <= index < ftd.size()):
                _, ea = internal.interface.addressOfRuntimeOrStatic(func)
                raise E.IndexOutOfBoundsError(u"{:s}.unused({:#x}, {:d}, {!s}) : The provided index ({:d}) is not within the range of the number of arguments ({:d}) for the specified function ({:#x}).".format('.'.join([__name__, 'type', cls.__name__]), ea, index, True if unused else False, index, ftd.size(), ea))

            # Grab the parameter and exchange its flags with our boolean.
            argument, FAI_UNUSED = ftd[index], getattr(idaapi, 'FAI_UNUSED', 0x10)
            preserve, value = (idaapi.as_uint32(integer) for integer in [~FAI_UNUSED, -1 if boolean else 0])
            result, argument.flags = argument.flags & FAI_UNUSED, idaapi.as_uint32((argument.flags & preserve) | (value & FAI_UNUSED))

            # Send the new flags back to our updater and return what we snagged.
            updater.send(ftd), updater.close()
            return True if result else False
        @utils.multicase(type=idaapi.tinfo_t, index=types.integer)
        @classmethod
        def unused(cls, type, index, boolean):
            updater = interface.tinfo.update_prototype_details(type)

            # Get the prototype and its details from the updater.
            prototype, ftd = builtins.next(updater)
            if not (0 <= index < ftd.size()):
                raise E.IndexOutOfBoundsError(u"{:s}.unused({!r}, {:d}, {!s}) : The provided index ({:d}) is not within the range of the number of arguments ({:d}) for the specified prototype.".format('.'.join([__name__, 'type', cls.__name__]), "{!s}".format(type), index, True if unused else False, index, ftd.size()))

            # Now we can grab the parameter in order to exchange its flags with our boolean.
            argument, FAI_UNUSED = ftd[index], getattr(idaapi, 'FAI_UNUSED', 0x10)
            preserve, value = (idaapi.as_uint32(integer) for integer in [~FAI_UNUSED, -1 if boolean else 0])
            result, argument.flags = argument.flags & FAI_UNUSED, idaapi.as_uint32((argument.flags & preserve) | (value & FAI_UNUSED))

            # That was it. We just need to send the details back to get our result.
            try:
                newinfo, _ = updater.send(ftd)
            except E.DisassemblerError:
                raise E.DisassemblerError(u"{:s}.unused({!r}, {:d}, {!s}) : Unable to remove the argument at index {:d} of the specified prototype \"{:s}\".".format('.'.join([__name__, 'type', cls.__name__]), "{!s}".format(type), index, True if unused else False, index, utils.string.escape("{!s}".format(prototype), '"')))
            finally:
                updater.close()
            return newinfo

    arg = parameter = argument  # XXX: ns alias

    class arguments(object):
        """
        This namespace allows one to interact the with the arguments
        belonging to a function prototype as a whole. This can allow
        one to count the number of arguments, or fetch all their names
        and types in their entirety.

        This namespace is aliased as ``function.type.args`` and ``function.type.parameters``.
        """
        @utils.multicase()
        def __new__(cls):
            '''Return the type for each of the parameters from the prototype for the current function.'''
            return cls(ui.current.address())
        @utils.multicase(types=internal.types.ordered)
        def __new__(cls, types):
            '''Modify the types for the parameters of the current function with the provided list of `types`.'''
            return cls(ui.current.address(), types)
        @utils.multicase(func=(idaapi.func_t, internal.types.integer))
        def __new__(cls, func):
            '''Return the type for each of the parameters from the prototype of the function `func`.'''
            tinfo, ftd = interface.tinfo.function_details(func)
            iterable = (ftd[index].type for index in builtins.range(ftd.size()))
            return [item for item in map(interface.tinfo.copy, iterable)]
        @utils.multicase(type=(internal.types.string, idaapi.tinfo_t))
        def __new__(cls, type):
            '''Return the type for each of the parameters from the prototype specified by `type`.'''
            tinfo = type if isinstance(type, idaapi.tinfo_t) else interface.tinfo.parse(None, type, idaapi.PT_SIL)
            if tinfo is None:
                raise E.InvalidTypeOrValueError(u"{:s}({!r}) : Unable to parse the specified string \"{:s}\" into a type.".format('.'.join([__name__, 'type', cls.__name__]), "{!s}".format(type), utils.string.escape("{!s}".format(type), '"')))
            result_and_parameters = interface.tinfo.function(tinfo)
            return [type for name, type, storage in result_and_parameters[1:]]
        @utils.multicase(func=(idaapi.func_t, internal.types.integer), types=internal.types.ordered)
        def __new__(cls, func, types):
            '''Modify the types for the parameters of the function `func` with the provided list of `types`.'''
            updater = interface.tinfo.update_function_details(func)

            # Grab the type and parameters so we can capture all of the ones that will be replaced.
            ti, ftd = builtins.next(updater)

            # Iterate through all of the parameters capturing all of the state that we'll return.
            results = []
            for idx in builtins.range(ftd.size()):
                farg = ftd[idx]
                aname, atype, aloc, acmt = farg.name, farg.type, farg.argloc, farg.cmt
                results.append((aname, interface.tinfo.copy(atype), aloc, acmt))

            # Now we should able to resize our details, and then update them with our input.
            ftd.resize(len(types))
            for index, item in enumerate(types):
                aname, ainfo = item if isinstance(item, internal.types.tuple) else ('', item)
                atype = ainfo if isinstance(ainfo, idaapi.tinfo_t) else interface.tinfo.parse(None, ainfo, idaapi.PT_SIL)
                if not atype:
                    ea, description = func if isinstance(func, internal.types.integer) else interface.range.start(func), ["{!s}".format(item) for item in types]
                    raise E.InvalidTypeOrValueError(u"{:s}({:#x}, {!r}) : Unable to parse the string \"{:s}\" specified for index {:d} of the parameters into a valid type.".format('.'.join([__name__, 'type', cls.__name__]), ea, description, utils.string.escape("{!s}".format(item), '"'), index))
                ftd[index].name, ftd[index].type = utils.string.to(aname), atype
            updater.send(ftd), updater.close()

            # The very last thing we need to do is to return our results. Even though we collected
            # all their information for safety, we return just the types for simplicity.
            return [item for _, item, _, _ in results]
        @utils.multicase(type=idaapi.tinfo_t, types=internal.types.ordered)
        def __new__(cls, type, types):
            '''Modify the types for the parameters of the prototype specified by `type` with the provided list of `types`.'''
            updater = interface.tinfo.update_prototype_details(type)

            # Start by getting the prototype and parameters prior to their modification.
            prototype, ftd = builtins.next(updater)

            # Iterate through all the parameters, and capture all of their attributes.
            results = []
            for idx in builtins.range(ftd.size()):
                farg = ftd[idx]
                aname, atype, aloc, acmt = farg.name, farg.type, farg.argloc, farg.cmt
                results.append((aname, interface.tinfo.copy(atype), aloc, acmt))

            # Now we should able to resize the details, and update them with our input.
            ftd.resize(len(types))
            for index, item in enumerate(types):
                aname, ainfo = item if isinstance(item, internal.types.tuple) else ('', item)
                atype = ainfo if isinstance(ainfo, idaapi.tinfo_t) else interface.tinfo.parse(None, ainfo, idaapi.PT_SIL)
                if not atype:
                    description = ["{!s}".format(item) for item in types]
                    raise E.InvalidTypeOrValueError(u"{:s}({!r}, {!r}) : Unable to parse the string \"{:s}\" specified for index {:d} of the parameters into a valid type.".format('.'.join([__name__, 'type', cls.__name__]), "{!s}".format(type), description, utils.string.escape("{!s}".format(item), '"'), index))
                ftd[index].name, ftd[index].type = utils.string.to(aname), atype

            # We should be good and only need to send things back to the updater.
            try:
                newinfo, _ = updater.send(ftd)
            except E.DisassemblerError:
                description = ["{!s}".format(item) for item in types]
                raise E.DisassemblerError(u"{:s}({!r}, {!r}) : Unable to update the arguments for the specified prototype \"{:s}\".".format('.'.join([__name__, 'type', cls.__name__]), "{!s}".format(type), description, utils.string.escape("{!s}".format(prototype), '"')))
            finally:
                updater.close()
            return newinfo

        @utils.multicase()
        @classmethod
        def count(cls):
            '''Return the number of parameters from the prototype of the current function.'''
            return cls.count(ui.current.address())
        @utils.multicase(func=(idaapi.func_t, internal.types.integer))
        @classmethod
        def count(cls, func):
            '''Return the number of parameters from the prototype of the function `func`.'''
            tinfo, ftd = interface.tinfo.function_details(func)
            return ftd.size()
        @utils.multicase(type=(internal.types.string, idaapi.tinfo_t))
        @classmethod
        def count(cls, type):
            '''Return the number of parameters from the prototype specified by `type`.'''
            tinfo = type if isinstance(type, idaapi.tinfo_t) else interface.tinfo.parse(None, type, idaapi.PT_SIL)
            if tinfo is None:
                raise E.InvalidTypeOrValueError(u"{:s}.count({!r}) : Unable to parse the specified string \"{:s}\" into a type.".format('.'.join([__name__, 'type', cls.__name__]), "{!s}".format(type), utils.string.escape("{!s}".format(type), '"')))
            prototype, details = interface.tinfo.prototype_details(tinfo)
            return prototype.get_nargs()

        @utils.multicase()
        @classmethod
        def types(cls):
            '''Return the types for each of the parameters from the prototype of the current function.'''
            return cls(ui.current.address())
        @utils.multicase(types=internal.types.ordered)
        @classmethod
        def types(cls, types):
            '''Modify the types for the parameters of the current function with the provided list of `types`.'''
            return cls(ui.current.address(), types)
        @utils.multicase(func=(idaapi.func_t, internal.types.integer))
        @classmethod
        def types(cls, func):
            '''Return the types for each of the parameters from the prototype of the function `func`.'''
            return cls(func)
        @utils.multicase(type=(internal.types.string, idaapi.tinfo_t))
        @classmethod
        def types(cls, type):
            '''Return the types for each of the parameters from the prototype specified by `type`.'''
            tinfo = type if isinstance(type, idaapi.tinfo_t) else interface.tinfo.parse(None, type, idaapi.PT_SIL)
            if tinfo is None:
                raise E.InvalidTypeOrValueError(u"{:s}.types({!r}) : Unable to parse the specified string \"{:s}\" into a type.".format('.'.join([__name__, 'type', cls.__name__]), "{!s}".format(type), utils.string.escape("{!s}".format(type), '"')))
            result_and_parameters = interface.tinfo.function(tinfo)
            return [type for name, type, storage in result_and_parameters[1:]]
        @utils.multicase(func=(idaapi.func_t, internal.types.integer, idaapi.tinfo_t), types=internal.types.ordered)
        @classmethod
        def types(cls, func, types):
            '''Modify the types for the parameters of the function `func` with the provided list of `types`.'''
            return cls(func, types)
        type = utils.alias(types, 'type.arguments')

        @utils.multicase()
        @classmethod
        def names(cls):
            '''Return the names for each of the parameters from the prototype of the current function.'''
            return cls.names(ui.current.address())
        @utils.multicase(func=(idaapi.func_t, internal.types.integer))
        @classmethod
        def names(cls, func):
            '''Return the names for each of the parameters from the prototype of the function `func`.'''
            ti, ftd = interface.tinfo.function_details(func)
            iterable = (ftd[index] for index in builtins.range(ftd.size()))
            return [utils.string.of(item.name) for item in iterable]
        @utils.multicase(type=(internal.types.string, idaapi.tinfo_t))
        @classmethod
        def names(cls, type):
            '''Return the names for each of the parameters from the prototype specified by `type`.'''
            tinfo = type if isinstance(type, idaapi.tinfo_t) else interface.tinfo.parse(None, type, idaapi.PT_SIL)
            if tinfo is None:
                raise E.InvalidTypeOrValueError(u"{:s}.names({!r}) : Unable to parse the specified string \"{:s}\" into a type.".format('.'.join([__name__, 'type', cls.__name__]), "{!s}".format(type), utils.string.escape("{!s}".format(type), '"')))
            result_and_parameters = interface.tinfo.function(tinfo)
            return [name for name, type, storage in result_and_parameters[1:]]
        @utils.multicase(names=internal.types.ordered)
        @classmethod
        def names(cls, names):
            '''Modify the names of the parameters in the prototype for the current function with the provided list of `names`.'''
            return cls.names(ui.current.address(), names)
        @utils.multicase(func=(idaapi.func_t, internal.types.integer), names=internal.types.ordered)
        @classmethod
        def names(cls, func, names):
            '''Modify the names for the parameters in the prototype for the function `func` with the provided list of `names`.'''
            _, ea = interface.addressOfRuntimeOrStatic(func)

            # Use a new updater to get the details from the specified function.
            updater = interface.tinfo.update_function_details(func)
            ti, ftd = builtins.next(updater)

            # Force all of the names we were given into string that we can actually apply. Afterwards
            # we check to see if we were given any extra that we need to warn the user about.
            strings = [item for item in map("{!s}".format, names)]
            if strings[ftd.size():]:
                discarded = ["\"{:s}\"".format(utils.string.escape(item, '"')) for item in strings[ftd.size():]]
                logging.warning(u"{:s}.names({:#x}, {!r}) : Discarding {:d} additional name{:s} ({:s}) that {:s} given for the specified function which has only {:d} parameter{:s}.".format('.'.join([__name__, 'type', cls.__name__]), ea, names, len(discarded), '' if len(discarded) == 1 else 's', ', '.join(discarded), 'was' if len(discarded) == 1 else 'were', ftd.size(), '' if ftd.size() == 1 else 's'))

            # Now we'll go through all of the available parameters, and update the names. If
            # we weren't given one, then we just assign an empty name to the funcarg_t.
            results = []
            for index in builtins.range(ftd.size()):
                farg, item = ftd[index], strings[index] if index < len(strings) else ''
                results.append(utils.string.of(farg.name))
                ftd[index].name = utils.string.to(item)

            # That was it, just need to update everything and return our results.
            updater.send(ftd), updater.close()
            return results
        @utils.multicase(type=idaapi.tinfo_t, names=internal.types.ordered)
        @classmethod
        def names(cls, type, names):
            '''Modify the parameter names for the prototype specified by `type` with the provided list of `names`.'''
            updater = interface.tinfo.update_prototype_details(type)

            # Getting the prototype and parameters prior to renaming things.
            prototype, ftd = builtins.next(updater)

            # Force all of the names we were given into strings that we can actually apply.
            # If we were given any extra, then we need to warn the user about them.
            strings = [item for item in map("{!s}".format, names)]
            if strings[ftd.size():]:
                discarded = ["\"{:s}\"".format(utils.string.escape(item, '"')) for item in strings[ftd.size():]]
                logging.warning(u"{:s}.names({!r}, {!r}) : Discarding {:d} additional name{:s} ({:s}) that {:s} given for the specified prototype which has only {:d} parameter{:s}.".format('.'.join([__name__, 'type', cls.__name__]), "{!s}".format(type), names, len(discarded), '' if len(discarded) == 1 else 's', ', '.join(discarded), 'was' if len(discarded) == 1 else 'were', ftd.size(), '' if ftd.size() == 1 else 's'))

            # Now we can update the names for each of the available parameters. If the
            # name is missing, then we can just use an empty name to clear the prameter.
            results = []
            for index in builtins.range(ftd.size()):
                farg, item = ftd[index], strings[index] if index < len(strings) else ''
                results.append(utils.string.of(farg.name))
                ftd[index].name = utils.string.to(item)

            # Finally we can send things back to the updater to get our final type.
            try:
                newinfo, _ = updater.send(ftd)
            except E.DisassemblerError:
                raise E.DisassemblerError(u"{:s}.names({!r}, {!r}) : Unable to update the argument names for the specified prototype \"{:s}\".".format('.'.join([__name__, 'type', cls.__name__]), "{!s}".format(type), names, utils.string.escape("{!s}".format(prototype), '"')))
            finally:
                updater.close()
            return newinfo
        name = utils.alias(names, 'type.arguments')

        @utils.multicase()
        @classmethod
        def iterate(cls):
            '''Yield the `(name, type, storage)` of each of the parameters from the prototype of the current function.'''
            return cls.iterate(ui.current.address())
        @utils.multicase(func=(idaapi.func_t, internal.types.integer))
        @classmethod
        def iterate(cls, func):
            '''Yield the `(name, type, storage)` of each of the parameters from the prototype of the function `func`.'''
            tinfo = interface.function.typeinfo(func)
            if tinfo is None:
                _, ea = interface.addressOfRuntimeOrStatic(func)
                raise E.DisassemblerError(u"{:s}.iterate({:#x}) : Unable to get the prototype for the specified function ({:#x}).".format('.'.join([__name__, 'type', cls.__name__]), ea, ea))

            # All we need to do is extract the type from the function, grab each component,
            # and then yield each of one them from the list while excluding the result.
            components = interface.tinfo.function(tinfo)
            for name, ti, storage in components[1:]:
                yield name, ti, storage
            return
        @utils.multicase(type=(internal.types.string, idaapi.tinfo_t))
        @classmethod
        def iterate(cls, type):
            '''Yield the `(name, type, storage)` of each of the parameters from the prototype specified by `type`.'''
            tinfo = type if isinstance(type, idaapi.tinfo_t) else interface.tinfo.parse(None, type, idaapi.PT_SIL)
            if tinfo is None:
                raise E.InvalidTypeOrValueError(u"{:s}.iterate({!r}) : Unable to parse the specified string \"{:s}\" into a type.".format('.'.join([__name__, 'type', cls.__name__]), "{!s}".format(type), utils.string.escape("{!s}".format(type), '"')))
            result_and_parameters = interface.tinfo.function(tinfo)
            return [(name, type, storage) for name, type, storage in result_and_parameters[1:]]

        @utils.multicase()
        @classmethod
        def registers(cls):
            '''Return the registers for each of the parameters from the prototype of the current function.'''
            return cls.registers(ui.current.address())
        @utils.multicase(func=(idaapi.func_t, internal.types.integer))
        @classmethod
        def registers(cls, func):
            '''Return the registers for each of the parameters from the prototype of the function `func`.'''
            tinfo = interface.function.typeinfo(func)
            if tinfo is None:
                _, ea = interface.addressOfRuntimeOrStatic(func)
                raise E.DisassemblerError(u"{:s}.registers({:#x}) : Unable to get the prototype for the specified function ({:#x}).".format('.'.join([__name__, 'type', cls.__name__]), ea, ea))

            # Gather all of the registers from each prototype component and return it.
            result, result_and_parameters = [], interface.tinfo.function(tinfo)
            for _, _, loc in result_and_parameters[1:]:
                if isinstance(loc, internal.types.tuple) and any(isinstance(item, interface.register_t) for item in loc):
                    reg, offset = loc
                    item = loc if all(isinstance(item, interface.register_t) for item in loc) else loc if offset else reg
                    result.append(item)
                continue
            return result
        @utils.multicase(type=(internal.types.string, idaapi.tinfo_t))
        @classmethod
        def registers(cls, type):
            '''Return the registers for each of the parameters from the prototype specified by `type`.'''
            tinfo = type if isinstance(type, idaapi.tinfo_t) else interface.tinfo.parse(None, type, idaapi.PT_SIL)
            if tinfo is None:
                raise E.InvalidTypeOrValueError(u"{:s}.registers({!r}) : Unable to parse the specified string \"{:s}\" into a type.".format('.'.join([__name__, 'type', cls.__name__]), "{!s}".format(type), utils.string.escape("{!s}".format(type), '"')))

            # Iterate through each prototype component, skipping over the result, and gather
            # the ones that are registers. If the the register offset is 0, then exclude it.
            result, result_and_parameters = [], interface.tinfo.function(tinfo)
            for _, _, loc in result_and_parameters[1:]:
                if isinstance(loc, internal.types.tuple) and any(isinstance(item, interface.register_t) for item in loc):
                    reg, offset = loc
                    item = loc if all(isinstance(item, interface.register_t) for item in loc) else loc if offset else reg
                    result.append(item)
                continue
            return result
        regs = utils.alias(registers, 'type.arguments')

        @utils.multicase()
        @classmethod
        def storage(cls):
            '''Return the storage location for each of the parameters from the prototype of the current function.'''
            return cls.storage(ui.current.address())
        @utils.multicase(func=(idaapi.func_t, internal.types.integer))
        @classmethod
        def storage(cls, func):
            '''Return the storage locations for each of the parameters from the prototype of the function `func`.'''
            tinfo = interface.function.typeinfo(func)
            if tinfo is None:
                _, ea = interface.addressOfRuntimeOrStatic(func)
                raise E.MissingTypeOrAttribute(u"{:s}.storage({:#x}) : Unable to get the prototype for the specified function ({:#x}).".format('.'.join([__name__, 'type', cls.__name__]), ea, ea))

            # All we need to do is extract the type from the function, grab each component,
            # and then yield each of one them from the list while excluding the result.
            result, result_and_parameters = [], interface.tinfo.function(tinfo)
            for _, _, item in result_and_parameters[1:]:
                if isinstance(item, internal.types.tuple) and isinstance(item[1], internal.types.integer):
                    register, offset = item
                    result.append(item if offset else register)
                else:
                    result.append(item)
                continue
            return result
        @utils.multicase(type=(internal.types.string, idaapi.tinfo_t))
        @classmethod
        def storage(cls, type):
            '''Return the storage locations for each of the parameters from the prototype specified by `type`.'''
            tinfo = type if isinstance(type, idaapi.tinfo_t) else interface.tinfo.parse(None, type, idaapi.PT_SIL)
            if tinfo is None:
                raise E.InvalidTypeOrValueError(u"{:s}.storage({!r}) : Unable to parse the specified string \"{:s}\" into a type.".format('.'.join([__name__, 'type', cls.__name__]), "{!s}".format(type), utils.string.escape("{!s}".format(type), '"')))

            # Iterate through all the prototype components other than the result,
            # and return each storage location excluding the offset if it is 0.
            result, result_and_parameters = [], interface.tinfo.function(tinfo)
            for _, _, location in result_and_parameters[1:]:
                if isinstance(location, internal.types.tuple) and isinstance(location[1], internal.types.integer):
                    register, offset = location
                    result.append(location if offset else register)
                else:
                    result.append(location)
                continue
            return result

        @utils.multicase(info=(internal.types.string, idaapi.tinfo_t))
        @classmethod
        def add(cls, info):
            '''Add the type in `info` as another parameter to the prototype of the current function.'''
            return cls.add(ui.current.address(), info, '')
        @utils.multicase(func=(idaapi.func_t, internal.types.integer, idaapi.tinfo_t), info=(internal.types.string, idaapi.tinfo_t))
        @classmethod
        def add(cls, func, info):
            '''Add the type in `info` as another parameter to the prototype of the function `func`.'''
            return cls.add(func, info, '')
        @utils.multicase(func=(idaapi.func_t, internal.types.integer), info=(internal.types.string, idaapi.tinfo_t), name=internal.types.string)
        @classmethod
        @utils.string.decorate_arguments('name', 'suffix')
        def add(cls, func, info, name, *suffix):
            '''Add the type in `info` with the given `name` as another parameter to the prototype of the function `func`.'''
            updater = interface.tinfo.update_function_details(func)

            # Grab the type and the details, and then resize it to add space for another parameter.
            ti, ftd = builtins.next(updater)
            index, _ = ftd.size(), ftd.resize(ti.get_nargs() + 1)

            # Convert all our parameters and update the index we allocated space for.
            res = name if isinstance(name, internal.types.tuple) else (name,)
            aname, ainfo = interface.tuplename(*(res + suffix)), interface.tinfo.parse(None, info, idaapi.PT_SIL) if isinstance(info, internal.types.string) else info
            ftd[index].name, ftd[index].type = utils.string.to(aname), ainfo

            # We should be good to go and we just need to return the index.
            updater.send(ftd), updater.close()
            return index
        @utils.multicase(type=idaapi.tinfo_t, info=(internal.types.string, idaapi.tinfo_t), name=internal.types.string)
        @classmethod
        @utils.string.decorate_arguments('name', 'suffix')
        def add(cls, type, info, name, *suffix):
            '''Add the type in `info` with the given `name` as another parameter to the prototype specified by `type`.'''
            updater = interface.tinfo.update_prototype_details(type)

            # Grab the prototype and parameters, and then resize them
            # to add the required space to append another parameter.
            prototype, ftd = builtins.next(updater)
            index, _ = ftd.size(), ftd.resize(prototype.get_nargs() + 1)

            # Now all we need to do is update the index we allocated space for.
            res = name if isinstance(name, internal.types.tuple) else (name,)
            aname, ainfo = interface.tuplename(*(res + suffix)), interface.tinfo.parse(None, info, idaapi.PT_SIL) if isinstance(info, internal.types.string) else info
            ftd[index].name, ftd[index].type = utils.string.to(aname), ainfo

            # To finish up, we just need to send our details back to get the final type.
            try:
                newinfo, _ = updater.send(ftd)
            except E.DisassemblerError:
                raise E.DisassemblerError(u"{:s}.add({!r}, {!r}, {!s}) : Unable to add an argument to the specified prototype \"{:s}\".".format('.'.join([__name__, 'type', cls.__name__]), "{!s}".format(type), "{!s}".format(info), utils.string.repr(aname), utils.string.escape("{!s}".format(prototype), '"')))
            finally:
                updater.close()
            return newinfo
        append = utils.alias(add, 'type.arguments')

        @utils.multicase()
        @classmethod
        def pop(cls):
            '''Pop the last parameter from the prototype of the current function and return its type.'''
            return cls.pop(ui.current.address(), -1)
        @utils.multicase(func=(idaapi.func_t, internal.types.integer))
        @classmethod
        def pop(cls, func):
            '''Pop the last parameter from the prototype of the function `func` and return its type.'''
            return cls.pop(func, -1)
        @utils.multicase(func=(idaapi.func_t, internal.types.integer), index=internal.types.integer)
        @classmethod
        def pop(cls, func, index):
            '''Pop the parameter at the specified `index` from the prototype of the function `func` and return its type.'''
            updater = interface.tinfo.update_function_details(func)

            # Grab the type and all the parameter information into a list,
            # and then pop the element at the index that was specified.
            ti, ftd = builtins.next(updater)
            iterable = (ftd[iarg] for iarg in builtins.range(ftd.size()))
            args = [(utils.string.of(arg.name), interface.tinfo.copy(arg.type), arg.argloc, arg.flags, utils.string.of(arg.cmt)) for arg in iterable]

            if -len(args) <= index < len(args):
                result = args.pop(index)
            else:
                _, ea = interface.addressOfRuntimeOrStatic(func)
                description = "only {:d} parameter".format(len(args)) if len(args) == 1 else "{:s} parameters".format("{:d}".format(len(args)) if args else 'no')
                range_description = "({:-d}..{:-d})".format(-len(args), len(args) - 1) if len(args) > 1 else "({:d})".format(0) if args else ''
                raise E.IndexOutOfBoundsError(u"{:s}.pop({:#x}, {:d}) : Unable to remove the specified parameter ({:d}) from the function at {:#x} which has {:s}{:s}.".format('.'.join([__name__, 'type', cls.__name__]), ea, index, index, ea, description, " {:s}".format(range_description) if range_description else ''))

            # Now we can resize the func_type_data_t, and then update
            # its elements with whatever parameter information is left.
            ftd.resize(len(args))
            for index, packed in enumerate(args):
                aname, atype, aloc, aflags, acmt = packed

                ftd[index].name = utils.string.to(aname)
                ftd[index].type = atype
                ftd[index].argloc = aloc
                ftd[index].flags = aflags
                ftd[index].cmt = utils.string.to(acmt)

            # That should've done it.. Send the updated func_type_data_t
            # back, close it, unpack our result, and then return the type.
            updater.send(ftd), updater.close()
            aname, atype, aloc, aflags, acmt = result
            return atype
        @utils.multicase(type=idaapi.tinfo_t, index=internal.types.integer)
        @classmethod
        def pop(cls, type, index):
            '''Pop the parameter at the specified `index` from the prototype specified by `type`.'''
            updater = interface.tinfo.update_prototype_details(type)

            # Grab the type and all the parameter information into a list,
            # and then pop the element at the index that was specified.
            ti, ftd = builtins.next(updater)
            iterable = (ftd[iarg] for iarg in builtins.range(ftd.size()))
            args = [(utils.string.of(arg.name), interface.tinfo.copy(arg.type), arg.argloc, arg.flags, utils.string.of(arg.cmt)) for arg in iterable]

            if -len(args) <= index < len(args):
                result = args.pop(index)
            else:
                description = "only {:d} parameter".format(len(args)) if len(args) == 1 else "{:s} parameters".format("{:d}".format(len(args)) if args else 'no')
                range_description = "({:-d}..{:-d})".format(-len(args), len(args) - 1) if len(args) > 1 else "({:d})".format(0) if args else ''
                raise E.IndexOutOfBoundsError(u"{:s}.pop({!r}, {:d}) : Unable to remove the parameter at the given index ({:d}) from the specified prototype which has {:s}{:s}.".format('.'.join([__name__, 'type', cls.__name__]), "{!s}".format(type), index, index, description, " {:s}".format(range_description) if range_description else ''))

            # Now we can resize the func_type_data_t, and then update
            # its elements with whatever parameter information is left.
            ftd.resize(len(args))
            for idx, packed in enumerate(args):
                aname, atype, aloc, aflags, acmt = packed

                ftd[idx].name = utils.string.to(aname)
                ftd[idx].type = atype
                ftd[idx].argloc = aloc
                ftd[idx].flags = aflags
                ftd[idx].cmt = utils.string.to(acmt)

            # That was it, so we just need to send our details back to get the final type.
            try:
                newinfo, _ = updater.send(ftd)
            except E.DisassemblerError:
                raise E.DisassemblerError(u"{:s}.pop({!r}, {:d}) : Unable to remove the parameter at the given index ({:d}) from the specified prototype \"{:s}\".".format('.'.join([__name__, 'type', cls.__name__]), "{!s}".format(type), index, index, utils.string.escape("{!s}".format(prototype), '"')))
            finally:
                updater.close()
            return newinfo

        @utils.multicase()
        @classmethod
        def locations(cls):
            '''Return the address of each of the parameters being passed to the function referenced at the current address.'''
            return cls.locations(ui.current.address())
        @utils.multicase(ea=internal.types.integer)
        @classmethod
        def locations(cls, ea):
            '''Return the address of each of the parameters being passed to the function referenced at address `ea`.'''
            iterable = interface.instruction.arguments(ea)
            return [ea for ea in iterable]
        @utils.multicase(func=(idaapi.func_t, internal.types.integer), ea=internal.types.integer)
        @classmethod
        def locations(cls, func, ea):
            '''Return the address of each of the parameters of the function `func` that are being passed to the function referenced at address `ea`.'''
            _, callee = interface.addressOfRuntimeOrStatic(func)
            refs = {ref for ref in interface.xref.any(callee, False)}
            if ea not in refs:
                logging.warning(u"{:s}.locations({!r}, {:#x}) : Ignoring the provided function ({:#x}) as the specified reference ({:#x}) is not referring to it.".format('.'.join([__name__, 'type', cls.__name__]), func, ea, address(func), ea))
            return cls.locations(ea)
        location = utils.alias(locations, 'type.arguments')

    args = parameters = arguments

    @utils.multicase()
    @classmethod
    def lumina(cls):
        '''Return whether the current function was identified by Lumina.'''
        return cls.lumina(ui.current.function())
    @utils.multicase(func=(idaapi.func_t, types.integer))
    @classmethod
    def lumina(cls, func):
        '''Return whether the function `func` was identified by Lumina.'''
        fn = func if isinstance(func, idaapi.func_t) else idaapi.get_func(func)
        return True if fn and interface.function.flags(fn, getattr(idaapi, 'FUNC_LUMINA', 0)) else False
    @utils.multicase(func=(idaapi.func_t, types.integer))
    @classmethod
    def lumina(cls, func, boolean):
        '''Modify the attributes of the function `func` to set it as a function identified by Lumina depending on the value of `boolean`.'''
        FUNC_LUMINA = getattr(idaapi, 'FUNC_LUMINA', 0)
        fn = interface.function.by(func, caller='.'.join([__name__, cls.__name__, 'lumina']))
        return interface.function.flags(fn, FUNC_LUMINA, -1 if boolean else 0) == FUNC_LUMINA

t = type # XXX: ns alias
prototype = utils.alias(type, 'type')
convention = cc = utils.alias(type.convention, 'type')
result = type.result # XXX: ns alias
arguments = args = type.arguments   # XXX: ns alias
argument = arg = type.argument  # XXX: ns alias
hide = utils.alias(type, 'hidden')

class xref(object):
    """
    This namespace is for navigating the cross-references (xrefs)
    associated with a function in the database. This allows for one
    to return all of the callers for a function, as well as all of
    the functions that it may call.

    This namespace is aliased as ``function.x``.

    Some of the functions within this namespace are also aliased as
    the following globals:

        ``function.up`` - Return all the addresses that reference a function
        ``function.down`` - Return the callable addresses referenced by a function

    Some ways to utilize this namespace can be::

        > print( function.xref.up() )
        > for ref in function.xref.down(): ...

    """

    ## referencing
    @utils.multicase()
    @classmethod
    def down(cls, **all):
        '''Yield the operand reference and its target ``ref_t`` for each instruction from the current function.'''
        return down(ui.current.function(), **all)
    @utils.multicase(func=(idaapi.func_t, types.integer))
    @classmethod
    def down(cls, func, **all):
        """Yield the operand reference and its target ``ref_t`` for each instruction from the function `func`.

        If `all` is true, then include branch instructions (that can exit the function) despite not having a target reference.
        """
        get_switch_info = idaapi.get_switch_info_ex if idaapi.__version__ < 7.0 else idaapi.get_switch_info

        # define a closure that will be used to merge multiple references for the same address.
        def Fmerge_references(refs):
            grouped = {}
            [grouped.setdefault(ref.address, []).append(ref) for ref in refs]

            # now we just need to take our dictionary of references and merge them.
            merged = {ea : functools.reduce(operator.or_, items) for ea, items in grouped.items() if items}

            # then we can go back through our list of refs and attempt to yield them in the
            # exact order that we received them.
            for ref in refs:
                ea = ref.ea
                if ea in merged:
                    yield merged.pop(ea)
                continue
            return

        # define a closure that will get us all of the related references so that we can process them.
        def Freferences(fn):
            branches = [instruction.is_call, instruction.is_branch]
            for ea in iterate(fn):

                # if it isn't code, then we skip it.
                if interface.address.flags(ea, idaapi.MS_CLS) != idaapi.FF_CODE:
                    continue

                # if it's a branching or call-type instruction that has no xrefs, and we're not
                # supposed to be keeping track of them...then log a warning for the user.
                elif not all.get('all', False) and not interface.xref.has(ea, True) and any(F(ea) for F in branches):
                    logging.warning(u"{:s}.down({:#x}) : Discovered the \"{:s}\" instruction at {:#x} that might've contained a reference but was unresolvable.".format('.'.join([__name__, cls.__name__]), interface.range.start(fn), utils.string.escape(database.instruction(ea), '"'), ea))
                    continue

                # now we need to check which code xrefs are actually going to be something we care
                # about by checking to see if there's an xref pointing outside our function.
                refs = []
                for ref in interface.xref.code(ea, True):
                    xref = ref.ea
                    if interface.node.identifier(xref):
                        pass

                    elif not contains(fn, xref):
                        refs.append(ref)

                    # if it's a branching or call-type instruction, but referencing non-code, then we care about it.
                    elif interface.address.flags(xref, idaapi.MS_CLS) != idaapi.FF_CODE and any(F(ea) for F in branches):
                        refs.append(ref)

                    # if we're recursive and there's a code xref that's referencing our entrypoint,
                    # then we're going to want that too.
                    elif interface.range.start(fn) == xref:
                        refs.append(ref)
                    continue

                # if we're at a branch related to the switch, then we need to ignore all of the code references that
                # we just collected. this is because the branch doesn't actually connect to them directly and instead
                # we need to modify the access of the data reference to union it with the executable flag.
                if get_switch_info(ea):
                    refs[:] = [ ref | 'x' for ref in interface.xref.data(ea, True) if not interface.node.identifier(ref.address) ]

                # otherwise we can simply add the data references to our current result for the current address.
                else:
                    [ refs.append(ref) for ref in interface.xref.data(ea, True) if not interface.node.identifier(ref.address) ]

                # now we merge our references, and then figure out which operand it came from.
                for ref in Fmerge_references(refs):
                    Fcheck_bits = (lambda access: 'x' in access) if 'x' in ref.access else (lambda access: 'w' in access) if 'w' in ref.access else (lambda access: 'w' not in access and any(bit in access for bit in 'r&'))
                    iterable = (opref for opref in interface.instruction.access(ea) if Fcheck_bits(opref.access))

                    # now we can create our opref_t and then yield both it and the ref_t to the caller.
                    yield next(iterable), ref

                # If we're supposed to always yield something but didn't get any references, then we need to
                # check if we're a branch instruction. If we were, then we need to yield an empty reference here.
                if all.get('all', False) and not refs and not interface.xref.has(ea, True) and any(F(ea) for F in branches):
                    iterable = (opref for opref in interface.instruction.access(ea) if 'x' in opref.access)
                    yield next(iterable), interface.ref_t()
                continue
            return

        # grab our function and then grab all of the references from it.
        fn = interface.function.by(func)
        iterable = Freferences(fn)
        return sorted(iterable)
    @utils.multicase(name=types.string)
    @classmethod
    @utils.string.decorate_arguments('name', 'suffix')
    def down(cls, name, *suffix, **all):
        '''Yield the operand reference and its target ``ref_t`` for each instruction from the function with the given `name`.'''
        res = (name,) + suffix
        func = interface.function.by(interface.tuplename(*res))
        return cls.down(func)

    @utils.multicase()
    @classmethod
    def up(cls):
        '''Return each address that references the current function.'''
        return up(ui.current.address())
    @utils.multicase(func=(idaapi.func_t, types.integer))
    @classmethod
    def up(cls, func):
        '''Return each address that references the function `func`.'''
        _, ea = interface.addressOfRuntimeOrStatic(func)
        iterable = interface.xref.any(ea, False)
        return sorted({ref for ref in iterable})
    @utils.multicase(name=types.string)
    @classmethod
    @utils.string.decorate_arguments('name', 'suffix')
    def up(cls, name, *suffix):
        '''Return each address that references the function with the given `name`'''
        res = (name,) + suffix
        func = interface.function.by(interface.tuplename(*res))
        _, ea = interface.addressOfRuntimeOrStatic(func)
        iterable = interface.xref.any(ea, False)
        return sorted({ref for ref in iterable})

    @utils.multicase()
    @classmethod
    def calls(cls):
        '''Return the operand reference for each call instruction that is referenced from the current function.'''
        return cls.calls(ui.current.function())
    @utils.multicase(func=(idaapi.func_t, types.integer))
    @classmethod
    def calls(cls, func, **all):
        '''Return the operand reference for each call instruction that is referenced from the function `func`.'''
        fn, results = interface.function.by(func), []
        for _, right in blocks.calls(fn):
            ea = interface.address.head(right - 1)
            results.extend(interface.instruction.access(ea))
        return results
    @utils.multicase(name=types.string)
    @classmethod
    @utils.string.decorate_arguments('name', 'suffix')
    def calls(cls, name, *suffix, **all):
        '''Return the operand reference for each call instruction that is referenced from the function with the given `name`.'''
        res = (name,) + suffix
        func = interface.function.by(interface.tuplename(*res))
        return cls.calls(func, **all)

    @utils.multicase()
    @classmethod
    def branches(cls):
        '''Return the operand reference for each branch instruction and is referenced from the current function.'''
        return cls.branches(ui.current.function())
    @utils.multicase(func=(idaapi.func_t, types.integer))
    @classmethod
    def branches(cls, func):
        '''Return the operand reference for each branch instruction that is referenced from the function `func`.'''
        fn, results = interface.function.by(func), []
        for _, right in blocks.branches(fn):
            ea = interface.address.head(right - 1)
            results.extend(interface.instruction.access(ea))
        return results
    @utils.multicase(name=types.string)
    @classmethod
    @utils.string.decorate_arguments('name', 'suffix')
    def branches(cls, name, *suffix):
        '''Return the operand reference for each branch instruction that is referenced from the function with the given `name`.'''
        res = (name,) + suffix
        func = interface.function.by(interface.tuplename(*res))
        return cls.branches(func)

    @utils.multicase(index=types.integer)
    @classmethod
    def argument(cls, index):
        '''Return the address of the parameter at the specified `index` being passed to the function reference at the current address.'''
        items = cls.arguments(ui.current.address())
        return items[index]
    @utils.multicase(ea=types.integer, index=types.integer)
    @classmethod
    def argument(cls, ea, index):
        '''Return the address of the parameter at the specified `index` being passed to the function reference at address `ea`.'''
        items = cls.arguments(ea)
        return items[index]
    arg = utils.alias(argument, 'xref')

    @utils.multicase()
    @classmethod
    def arguments(cls):
        '''Return a list of addresses for the parameters being passed to the function reference at the current address.'''
        return cls.arguments(ui.current.address())
    @utils.multicase(ea=types.integer)
    @classmethod
    def arguments(cls, ea):
        '''Return a list of addresses for the parameters being passed to the function reference at address `ea`.'''
        iterable = interface.instruction.arguments(ea)
        return [ea for ea in iterable]
    args = utils.alias(arguments, 'xref')

x = xref    # XXX: ns alias
up, down = utils.alias(xref.up, 'xref'), utils.alias(xref.down, 'xref')
calls, branches = utils.alias(xref.calls, 'xref'), utils.alias(xref.branches, 'xref')
