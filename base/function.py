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
    return offset(func, 0)
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
    return address(func, 0)
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
        for start, end in cls(func):
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
        for ch, _ in cls(fn):
            for ea, delta in chunk.points(fn, ch):
                yield ea, delta
            continue
        return
    stackpoints = utils.alias(points, 'chunks')

iterate = utils.alias(chunks.iterate, 'chunks')
contains = utils.alias(chunks.contains, 'chunks')
register = utils.alias(chunks.register, 'chunks')

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

    """
    @utils.multicase()
    def __new__(cls):
        '''Return a tuple containing the bounds of the function chunk at the current address.'''
        return cls(ui.current.address())
    @utils.multicase(ea=types.integer)
    def __new__(cls, ea):
        '''Return a tuple containing the bounds of the function chunk at the address `ea`.'''
        area = cls.at(ea, ea)
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
        start, end = cls(ea)
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
        return cls.points(ui.current.function(), ui.current.address())
    @utils.multicase(ea=types.integer)
    @classmethod
    def points(cls, ea):
        '''Yield the `(address, delta)` for each stack point where the delta changes in the chunk containing the address `ea`.'''
        fn = interface.function.by(ea)
        return cls.points(fn, ea)
    @utils.multicase(func=(idaapi.func_t, types.integer), ea=types.integer)
    @classmethod
    def points(cls, func, ea):
        '''Yield the `(address, delta)` for each stack point where the delta changes in the chunk containing the address `ea` belonging to the function `func`.'''
        fn, ch = interface.function.by(func), idaapi.get_fchunk(ea)

        # If we were unable to get the function chunk for the provided address,
        # then IDA didn't calculate any stack deltas for what was requested.
        if ch is None:
            return

        # If this is a function tail, then we need to use the function we got
        # to filter out just the desired addresses and get their stackpoints.
        if ch.flags & idaapi.FUNC_TAIL and hasattr(getattr(fn, 'points', None), '__getitem__'):
            Fcontains, owner = interface.range.bounds(ch).contains, fn

            # Now all we need to do is to grab all of the stack points for
            # the function, and filter them by our chunk's boundaries.
            points = (owner.points[index] for index in builtins.range(owner.pntqty))
            iterable = ((point.ea, point.spd) for point in points if Fcontains(point.ea))

        # A non-tail just requires us to iterate through the points stored in the
        # chunk, so we can yield the address and delta for each individual point.
        elif hasattr(ch, 'points') and hasattr(ch.points, '__getitem__'):
            points = (ch.points[index] for index in builtins.range(ch.pntqty))
            iterable = ((point.ea, point.spd) for point in points)

        # If we were completely unable to access the correct attributes, then we
        # need to do all of the work ourselves. We walk the entire function, filter
        # for deltas in our chunk, sort them, and then yield each of them one-by-one.
        else:
            spd, points = 0, {}
            for ea in chunks.iterate(fn):
                res = idaapi.get_spd(fn, ea)
                if res == spd:
                    continue
                points[ea], spd = res, spd

            filtered = filter(interface.range.bounds(ch).contains, points)
            iterable = ((ea, points[ea]) for ea in sorted(filtered))

        # We have our iterator of points, so all we need to do is to unpack each
        # one and yield it to our caller.
        for ea, spd in iterable:
            yield ea, spd
        return
    stackpoints = utils.alias(points, 'chunk')

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
        left, _ = cls()
        return left
    @utils.multicase(ea=types.integer)
    @classmethod
    def top(cls, ea):
        '''Return the top address of the chunk at address `ea`.'''
        left, _ = cls(ea)
        return left
    @utils.multicase(ea=types.integer, address=types.integer)
    @classmethod
    def top(cls, ea, address):
        '''Change the top address of the chunk at address `ea` to the specified `address`.'''
        bounds = cls(ea)
        left, _ = bounds

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
        _, right = cls()
        return right
    @utils.multicase(ea=types.integer)
    @classmethod
    def bottom(cls, ea):
        '''Return the bottom address of the chunk at address `ea`.'''
        _, right = cls(ea)
        return right
    @utils.multicase(ea=types.integer, address=types.integer)
    @classmethod
    def bottom(cls, ea, address):
        '''Change the bottom address of the chunk at address `ea` to the specified `address`.'''
        bounds = cls(ea)
        left, right = bounds
        if not idaapi.set_func_end(left, address):
            raise E.DisassemblerError(u"{:s}.bottom({:#x}, {:#x}) : Unable to modify the bottom of the specified chunk with `{:s}({:#x}, {:#x})`.".format('.'.join([__name__, cls.__name__]), ea, address, utils.pycompat.fullname(idaapi.set_func_end), left, address))
        return right

    @utils.multicase()
    @classmethod
    def address(cls):
        '''Return the top address of the function chunk containing the current address.'''
        return cls.address(ui.current.address(), 0)
    @utils.multicase(ea=types.integer)
    @classmethod
    def address(cls, ea):
        '''Return the top address of the function chunk containing the address `ea`.'''
        return cls.address(ea, 0)
    @utils.multicase(ea=types.integer, offset=types.integer)
    @classmethod
    def address(cls, ea, offset):
        '''Return the address of the function chunk containing the address `ea` and add the provided `offset` to it.'''
        left, _ = cls(ea)
        return left + offset

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
        left, _ = cls(ea)
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
        return cls(start)
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
        return cls(ea)
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
        bounds = cls(ea)
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
        return cls.iterate(func, fc_flags, **external)
    @utils.multicase(func=(idaapi.func_t, types.integer), flags=types.integer)
    @classmethod
    def iterate(cls, func, flags, **silent):
        '''Returns each ``idaapi.BasicBlock`` from the flowchart built with the specified `flags` (``idaapi.FC_*``) for the function `func`.'''
        fn, FC_CALL_ENDS, has_calls = interface.function.by(func), getattr(idaapi, 'FC_CALL_ENDS', 0x20), hasattr(idaapi, 'FC_CALL_ENDS')
        boundaries = [bounds for bounds in chunks(fn)]

        # iterate through all the basic-blocks in the flow chart and yield
        # each of them back to the caller. we need to ensure that the bounds
        # are actually contained by the function, so we collect this too.
        for bb in cls.flowchart(fn, flags):
            left, right = interface.range.unpack(bb)
            bounds = interface.range.bounds(bb)
            ea, _ = bounds

            # if we're unable to split up calls, then we need to traverse this
            # block so that we can figure out where we need to split.
            if not has_calls and flags & FC_CALL_ENDS:
                start, stop, locations = left, right, [ea for ea in block.iterate(bb) if interface.instruction.is_call(ea)]
                for item in locations:
                    left, right = start, idaapi.next_not_tail(item)
                    yield idaapi.BasicBlock(bb.id, interface.range.pack(left, right), bb._fc)
                    start = right

                # if the addresses are diffrent, then we have one more block to yield.
                if start < stop:
                    yield idaapi.BasicBlock(bb.id, interface.range.pack(start, stop), bb._fc)

                # if they're the same and we didn't have to chop it up, then this is external.
                elif start == stop and not locations:
                    yield idaapi.BasicBlock(bb.id, interface.range.pack(start, stop), bb._fc)

            # if we've been asked to be silent, then just yield what we got.
            elif silent.get('silent', False):
                yield bb

            # unpack the boundaries of the basic block to verify it's in one
            # of them, so that way we can yield it to the user if so.
            elif any(start <= ea <= stop for start, stop in boundaries) and left != right:
                yield bb

            # otherwise warn the user about it just in case they're processing
            # them and are always expecting an address within the function.
            else:
                f, api, Flogging = interface.range.start(fn), idaapi.FlowChart, logging.warning if flags & idaapi.FC_NOEXT else logging.info
                Flogging(u"{:s}.iterate({:#x}, {:#x}{:s}) : The current block {!s} ({:s}) being returned by `{:s}` is outside the boundaries of the requested function ({:#x}).".format('.'.join([__name__, cls.__name__]), f, flags, ", {:s}".format(utils.string.kwargs(silent)) if silent else '', bb, bounds, '.'.join([api.__module__, api.__name__]), f))
                yield bb
            continue
        return

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
    def select(cls, tag, *included, **boolean):
        '''Query the basic blocks of the current function for the given `tag` or any others that should be `included`.'''
        res = {tag} | {item for item in included}
        boolean['included'] = {item for item in boolean.get('included', [])} | res
        return cls.select(ui.current.function(), **boolean)
    @utils.multicase(func=(idaapi.func_t, types.integer), tag=types.string)
    @classmethod
    @utils.string.decorate_arguments('tag', 'And', 'Or', 'require', 'requires', 'required', 'include', 'includes', 'included')
    def select(cls, func, tag, *included, **boolean):
        '''Query the basic blocks of the function `func` for the given `tag` or any others that should be `included`.'''
        res = {tag} | {item for item in included}
        boolean['included'] = {item for item in boolean.get('included', [])} | res
        return cls.select(func, **boolean)
    @utils.multicase(func=(idaapi.func_t, types.integer), tags=types.unordered)
    @classmethod
    @utils.string.decorate_arguments('tags', 'And', 'Or', 'require', 'requires', 'required', 'include', 'includes', 'included')
    def select(cls, func, tags, *included, **boolean):
        '''Query the basic blocks of the function `func` for the given `tags` or any others that should be `included`.'''
        res = {item for item in tags} | {item for item in included}
        boolean['included'] = {item for item in boolean.get('included', [])} | res
        return cls.select(func, **boolean)
    @utils.multicase(func=(idaapi.func_t, types.integer))
    @classmethod
    @utils.string.decorate_arguments('And', 'Or', 'require', 'requires', 'required', 'include', 'includes', 'included')
    def select(cls, func, **boolean):
        """Query the basic blocks of the function `func` for any of the tags specified by `boolean` and yield a tuple for each matching basic block with selected tags and values.

        If `require` is given as an iterable of tag names then require that each returned block uses them.
        If `include` is given as an iterable of tag names then include the tags for each returned block if available.
        """
        target, flags = interface.function.by(func), getattr(idaapi, 'FC_NOEXT', 2) | getattr(idaapi, 'FC_CALL_ENDS', 0x20)

        # Turn all of our parameters into a dict of sets that we can iterate through.
        boolean = {key : {item for item in value} if isinstance(value, types.unordered) else {value} for key, value in boolean.items()}

        # Grab the addresses that are actually tagged into a set, and then the basic
        # blocks in an ordered dictionary so that we can union them for our results.
        available = {ea for ea in internal.comment.contents.address(interface.range.start(target), target=interface.range.start(target))}
        order, iterable = [], ((item, interface.range.bounds(item)) for item in blocks.iterate(target, flags))
        results = {bounds.left : [order.append(bounds.left), item].pop(1) for item, bounds in iterable }

        # Now we just need to union both our tagged addresses with the ones which
        # are basic-blocks to get a list of the selected addresses.
        selected = {ea for ea in available} & {ea for ea in order}
        ordered = [ea for ea in order if ea in selected]

        # If nothing specific was queried, then iterate through our ordered
        # blocks and yield absolutely everything that we found.
        if not boolean:
            for ea in ordered:
                ui.navigation.analyze(ea)
                address = block.tag(ea)
                if address: yield interface.range.bounds(results[ea]), address
            return

        # Collect the tagnames being queried as specified by the user.
        included, required = ({item for item in itertools.chain(*(boolean.get(B, []) for B in Bs))} for Bs in [['Or', 'include', 'included', 'includes'], ['And', 'require', 'required', 'requires']])

        # Walk through every tagged address and cross-check it against the query.
        for ea in ordered:
            ui.navigation.analyze(ea)
            collected, address = {}, block.tag(ea)

            # included is the equivalent of Or(|) and yields a block if any of the specified tagnames are used.
            collected.update({key : value for key, value in address.items() if key in included})

            # required is the equivalent of And(&) which yields a block only if it uses all of the specified tagnames.
            if required:
                if required & six.viewkeys(address) == required:
                    collected.update({key : value for key, value in address.items() if key in required})
                else: continue

            # If anything was collected (matched), then yield the block and the matching tags.
            if collected: yield interface.range.bounds(results[ea]), collected
        return

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
        '''Return the addresses of all the instructions that branch to the current basic block.'''
        return cls.before(ui.current.address())
    @utils.multicase(ea=types.integer)
    @classmethod
    def before(cls, ea):
        '''Return the addresses of all the instructions that branch to the basic block at address `ea`.'''
        res = blocks.at(ea)
        return cls.before(res)
    @utils.multicase(bounds=interface.bounds_t)
    @classmethod
    def before(cls, bounds):
        '''Return the addresses of all the instructions that branch to the basic block identified by `bounds`.'''
        bb = cls.at(bounds)
        return cls.before(bb)
    @utils.multicase(bb=idaapi.BasicBlock)
    @classmethod
    def before(cls, bb):
        '''Return the addresses of all the instructions that branch to the basic block `bb`.'''
        return [ idaapi.prev_not_tail(interface.range.end(bb)) for bb in bb.preds() ]
    predecessors = preds = utils.alias(before, 'block')

    @utils.multicase()
    @classmethod
    def after(cls):
        '''Return the addresses of all the instructions that the current basic block leaves to.'''
        return cls.after(ui.current.address())
    @utils.multicase(ea=types.integer)
    @classmethod
    def after(cls, ea):
        '''Return the addresses of all the instructions that the basic block at address `ea` leaves to.'''
        bb = cls.at(ea)
        return cls.after(bb)
    @utils.multicase(bounds=interface.bounds_t)
    @classmethod
    def after(cls, bounds):
        '''Return the addresses of all the instructions that branch to the basic block identified by `bounds`.'''
        bb = cls.at(bounds)
        return cls.after(bb)
    @utils.multicase(bb=idaapi.BasicBlock)
    @classmethod
    def after(cls, bb):
        '''Return the addresses of all the instructions that branch to the basic block `bb`.'''
        return [interface.range.start(bb) for bb in bb.succs()]
    successors = succs = utils.alias(after, 'block')

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
        DEFCOLOR, ea = 0xffffffff, interface.range.start(bb)

        # first thing to do is to read the tags for the address. this
        # gives us "__extra_prefix__", "__extra_suffix__", and "__name__".
        res = internal.tags.address.get(ea)

        # next, we're going to replace the one implicit tag that we
        # need to handle...and that's the "__color__" tag.
        col = interface.function.blockcolor(bb)
        if col not in {None, DEFCOLOR}: res.setdefault('__color__', col)

        # that was pretty much it, so we can just return our results.
        return res
    @utils.multicase(bb=idaapi.BasicBlock, key=types.string)
    @classmethod
    @utils.string.decorate_arguments('key', 'value')
    def tag(cls, bb, key):
        '''Returns the value of the tag identified by `key` from the ``idaapi.BasicBlock`` given in `bb`.'''
        res = cls.tag(bb)
        if key in res:
            return res[key]
        bounds = interface.range.bounds(bb)
        raise E.MissingTagError(u"{:s}.tag({!s}, {!r}) : Unable to read the specified tag (\"{:s}\") from the basic block ({:s}).".format(__name__, bounds, key, utils.string.escape(key, '"'), bounds))
    @utils.multicase(bb=idaapi.BasicBlock, key=types.string)
    @classmethod
    @utils.string.decorate_arguments('key', 'value')
    def tag(cls, bb, key, value):
        '''Sets the value for the tag `key` to `value` in the ``idaapi.BasicBlock`` given by `bb`.'''
        DEFCOLOR, ea = 0xffffffff, interface.range.start(bb)

        # the only real implicit tag we need to handle is "__color__", because our
        # database.tag function does "__extra_prefix__", "__extra_suffix__", and "__name__".
        if key == '__color__':
            res = interface.function.blockcolor(bb, value)
            [ interface.address.color(ea, value) for ea in cls.iterate(bb) ]
            return None if res == DEFCOLOR else res

        # now we can passthrough to database.tag for everything else.
        return internal.tags.address.set(ea, key, value)
    @utils.multicase(bb=idaapi.BasicBlock, key=types.string, none=types.none)
    @classmethod
    @utils.string.decorate_arguments('key')
    def tag(cls, bb, key, none):
        '''Removes the tag identified by `key` from the ``idaapi.BasicBlock`` given by `bb`.'''
        DEFCOLOR, ea = 0xffffffff, interface.range.start(bb)

        # if the '__color__' tag was specified, then explicitly clear it.
        if key == '__color__':
            res = interface.function.blockcolor(bb, DEFCOLOR)
            [ interface.address.color(ea, DEFCOLOR) for ea in cls.iterate(bb) ]
            return None if res == DEFCOLOR else res

        # passthrough to database.tag for removing the ones we don't handle.
        return internal.tags.address.remove(ea, key, none)

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
    This namespace is for getting information about the selected
    function's frame. By default, this namespace will return a
    ``structure_t`` representing the frame belonging to the specified
    function. The returned frame will include any preserved registers
    so that offset 0 will point at the beginning of the parameters.

    Some ways of using this can be::

        > print( function.frame() )
        > print( hex(function.frame.id(ea)) )
        > sp = function.frame.delta(ea)

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

    @utils.multicase()
    @classmethod
    def new(cls):
        '''Add an empty frame to the current function.'''
        fn = ui.current.function()
        return cls.new(fn, 0, idaapi.get_frame_retsize(fn), 0)
    @utils.multicase(lvars=types.integer, args=types.integer)
    @classmethod
    def new(cls, lvars, args):
        '''Add a frame to the current function using the sizes specified by `lvars` for local variables, and `args` for arguments.'''
        fn = ui.current.function()
        return cls.new(fn, lvars, idaapi.get_frame_retsize(fn), args)
    @utils.multicase(lvars=types.integer, regs=types.integer, args=types.integer)
    @classmethod
    def new(cls, lvars, regs, args):
        '''Add a frame to the current function using the sizes specified by `lvars` for local variables, `regs` for frame registers, and `args` for arguments.'''
        return cls.new(ui.current.function(), lvars, regs, args)
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
        return cls(fn)

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

    @utils.multicase()
    @classmethod
    def delta(cls):
        '''Returns the stack delta for the current address within its function.'''
        return cls.delta(ui.current.address())
    @utils.multicase(ea=types.integer)
    @classmethod
    def delta(cls, ea):
        '''Returns the stack delta for the address `ea` within its given function.'''
        fn, ea = interface.function.by(ea), interface.address.inside(ea)
        return idaapi.get_spd(fn, ea)
    @utils.multicase(func=(idaapi.func_t, types.integer), ea=types.integer)
    @classmethod
    def delta(cls, func, ea):
        '''Returns the stack delta for the address `ea` within the function `func`.'''
        fn, ea = interface.function.by(func), interface.address.inside(ea)
        return idaapi.get_spd(fn, ea)

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
            '''Yield the `(offset, name, size)` of each argument belonging to the current function.'''
            return cls(ui.current.address())
        @utils.multicase(func=(idaapi.func_t, types.integer))
        def __new__(cls, func):
            '''Yield the `(offset, name, size)` of each argument belonging to the function `func`.'''
            _, ea = interface.addressOfRuntimeOrStatic(func)

            # first we'll need to check if there's a tinfo_t for the address to
            # give it priority over the frame. then we can grab its details.
            if type.has(ea):
                tinfo = type(ea)
                _, ftd = interface.tinfo.function_details(ea, tinfo)

                # iterate through the parameters and collect only arguments that
                # are allocated on the stack so that we can use their information
                # when yielding our results.
                items = []
                for index in builtins.range(ftd.size()):
                    arg, loc = ftd[index], ftd[index].argloc

                    # not allocated on the stack? then we skip it..
                    if loc.atype() != idaapi.ALOC_STACK:
                        continue

                    # extract the stack offset, and then add the argument
                    # information that we collected to our list.
                    stkoff = loc.stkoff()
                    items.append((index, stkoff, utils.string.of(arg.name), arg.type))

                # our results shouldn't have duplicates, but they might. actually,
                # our results could technically be overlapping too. still, this is
                # just to priority the tinfo_t and we only care about the stkoff.
                locations = {}
                for index, offset, name, tinfo in items:
                    if operator.contains(locations, offset):
                        old_index, old_name, _ = locations[offset]
                        logging.warning(u"{:s}({:#x}) : Overwriting the parameter {:s}(index {:d}) for function ({:#x}) due to parameter {:s}(index {:d}) being allocated at the same frame offset ({:+#x}).".format('.'.join([__name__, cls.__name__]), ea, "\"{:s}\" ".format(utils.string.escape(old_name, '"')) if old_name else '', old_index, ea, "\"{:s}\" ".format(utils.string.escape(name, '"')) if name else '', index, offset))
                    locations[offset] = (index, name, tinfo)

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
                    results.append((0, None, delta))

                # now we can iterate through all our locations and yield each one.
                for offset in sorted(locations):
                    _, name, ti = locations[offset]
                    results.append((offset, name or None, ti.get_size()))
                return results

            # to proceed, we need to know the function to get its frame sizes.
            else:
                fn = idaapi.get_func(ea)

            # once we have our locations, we can grab a fragment from the frame
            # and yield all of the members that are considered as arguments.
            current, base = 0, idaapi.frame_off_args(fn)
            for offset, size, content in structure.fragment(fr.id, base, structure.size(fr.id) - base):
                stkoff = offset - base

                # check our locations to see if we have any type information for
                # the given stkoff so that way we can prioritize it.
                if operator.contains(locations, stkoff):
                    index, tname, tinfo = locations.pop(stkoff)

                    # grab the tinfo name and tinfo size. if the name wasn't found,
                    # then fall back to using the member name from the frame.
                    name, tsize = tname or content.get('__name__', None), tinfo.get_size()

                    # if our member size matches our tinfo size, then we can yield it.
                    if tsize == size:
                        results.append((stkoff, name, tsize))

                    # if the tinfo size is smaller then the member's, then we're
                    # going to need to pad it up to the expected member size.
                    elif tsize < size:
                        results.append((stkoff, name, tsize))
                        results.append((stkoff + tsize, None, size - tsize))

                    # otherwise, the member size is smaller than the tinfo size.
                    # if this is the case, then we need to use the member size
                    # but log a warning that we're ignoring the size of the tinfo.
                    else:
                        logging.warning(u"{:s}({:#x}) : Ignoring the type size for parameter {:s}(index {:d}) for function ({:#x}) due to the frame member at offset ({:+#x}) being smaller ({:+#x}).".format('.'.join([__name__, cls.__name__]), ea, "\"{:s}\" ".format(utils.string.escape(tname, '"')) if tname else '', index, ea, stkoff, size))
                        results.append((stkoff, name, size))

                # otherwise we'll just yield the information from the member.
                else:
                    results.append((stkoff, content.get('__name__', None), size))

                # update our current offset and proceed to the next member.
                current = stkoff + size

            # iterate through all of the locations that we have left.
            for stkoff in sorted(locations):
                _, name, ti = locations[stkoff]

                # if our current position is not pointing at the expected stkoff,
                # then we need to yield some padding that will put us there.
                if current < stkoff:
                    results.append((current, None, stkoff - current))

                # now we can yield the next member and adjust our current position.
                results.append((stkoff, name or None, ti.get_size()))
                current = stkoff + ti.get_size()
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
            if not any(Finstruction(ea) for Finstruction in [interface.instruction.is_call, interface.instruction.is_branch]):
                raise E.MissingTypeOrAttribute(u"{:s}.location({:#x}) : The instruction at the specified address ({:#x}) is not a function call.".format('.'.join([__name__, cls.__name__]), ea, ea))

            items = idaapi.get_arg_addrs(ea)
            if items is None:
                raise E.DisassemblerError(u"{:s}.location({:#x}) : Unable to retrieve the initialization addresses for the arguments to the function call at {:#x}.".format('.'.join([__name__, cls.__name__]), ea, ea))
            return [ea for ea in items]
        @utils.multicase(ea=types.integer, index=types.integer)
        @classmethod
        def location(cls, ea, index):
            '''Return the initialization address for the parameter at `index` for the function call at `ea`.'''
            items = cls.location(ea)
            if not (0 <= index < len(items)):
                raise E.InvalidTypeOrValueError(u"{:s}.location({:#x}, {:d}) : The requested argument index ({:d}) for the function call at address {:#x} is not within the bounds of the function's arguments ({:d} <= {:d} < {:d}).".format('.'.join([__name__, cls.__name__]), ea, index, index, ea, 0, index, len(items)))
            return items[index]
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
            bits, tilookup = interface.database.bits(), {
                8: idaapi.BT_INT8, 16: idaapi.BT_INT16, 32: idaapi.BT_INT32,
                64: idaapi.BT_INT64, 128: idaapi.BT_INT128, 80: idaapi.BTF_TBYTE,
            }

            # Then build an array_type_data_t for absolutely everything else.
            at, byte = idaapi.array_type_data_t(), idaapi.tinfo_t()
            byte.create_simple_type(idaapi.BTF_BYTE)
            at.base, at.nelems, at.elem_type = 0, 0, byte

            # If we have no type information, then we can only process arguments if we're within
            # a function. If we're not not part of a functon, then we log a warning and bail.
            if not has_tinfo:
                if not fn:
                    logging.warning(u"{:s}.iterate({:#x}) : Unable to iterate through the arguments for the given function ({:#x}) due to missing type information.".format('.'.join([__name__, cls.__name__]), ea, ea))

                # If our function's regargqty is larger than zero, then we're supposed to extract the
                # regargs directly out of the func_t.
                elif fn.regargqty:
                    items = []

                    # If regargqty is set, but regargs is None...then we need to call read_regargs on our
                    # fn to get IDA to actually read it...The funny thing is, on earlier versions of IDA
                    # it seems that read_regargs won't always allocate an iterator...so this means that
                    # we manually make it a list and then this way we can iterate through the fucker.
                    idaapi.read_regargs(fn) if fn.regargs is None else None
                    if isinstance(fn.regargs, idaapi.regarg_t):
                        regargs = [fn.regargs]
                    else:
                        regargs = [fn.regargs[index] for index in builtins.range(fn.regargqty)]

                    # Iterate through all of our arguments and grab the register, the type information, and
                    # argument name out of the register argument.
                    for index, regarg in enumerate(regargs):
                        ti = idaapi.tinfo_t()

                        # Deserialize the type information that we received from the register argument.
                        if ti.deserialize(None, regarg.type, None):
                            items.append((regarg, ti))

                        # If we failed, then log a warning and try to append a void* as a placeholder.
                        elif ti.deserialize(None, bytes(bytearray([idaapi.BT_PTR, idaapi.BT_VOID])), None):
                            logging.warning(u"{:s}.iterate({:#x}) : Using the type {!r} as a placeholder due to being unable to decode the type information ({!s}) for the argument at index {:d}.".format('.'.join([__name__, cls.__name__]), ea, ti._print(), regarg.type, index))
                            items.append((regarg, ti))

                        # If we couldn't even create a void*, then this is a critical failure and we
                        # really need to get the argument size correct. So, we just look it up.
                        else:
                            if not operator.contains(tilookup, bits) or not ti.deserialize(None, bytes(bytearray([tilookup[bits]])), None):
                                raise E.DisassemblerError(u"{:s}.iterate({:#x}) : Unable to create a type that fits within the number of bits for the database ({:d}).".format('.'.join([__name__, cls.__name__]), ea, bits))
                            logging.critical(u"{:s}.iterate({:#x}) : Falling back to the type {!r} as a placeholder due to being unable to cast the type information ({!r}) for the argument at index {:d}.".format('.'.join([__name__, cls.__name__]), ea, ti._print(), regarg.type, index))
                            items.append((regarg, ti))
                        continue

                    # Now that we have the regarg and its tinfo_t, we just need to extract
                    # its properties to turn it into a register_t and grab its name.
                    for regarg, ti in items:
                        try:
                            reg = instruction.architecture.by_indexsize(regarg.reg, ti.get_size())
                        except KeyError:
                            reg = instruction.architecture.by_index(regarg.reg)
                        yield reg, ti, utils.string.of(regarg.name)

                    # We processed the registers, so we can fallthrough to the next one.

                # If we have a frame, then we do our best to figure out the parameters from it.
                if fn and idaapi.get_frame(ea):
                    fr, asize, rsize = frame(ea), cls.size(ea), fn.frregs + idaapi.get_frame_retsize(fn)

                    # Before we start checking the frame, though, we need to make sure that IDA
                    # didn't have any problems calculating the stackpoints. If so, then we need
                    # to access the member differently using an "inexact" methodology.
                    Flocation = operator.attrgetter('offset') if Fproblem(PR_BADSTACK, ea) else utils.fidentity

                    # Now we can grab the fragment of the structure containing the parameters. If
                    # there's no content, then skip it and move onto the next member.
                    for offset, size, content in structure.fragment(fr.id, fr.size - asize, asize):
                        if not content:
                            continue

                        # Now we can calculate our location and create a default type for it.
                        aoffset = offset - fr.size + asize
                        location, aname = interface.location_t(aoffset + rsize, size), interface.tuplename('arg', aoffset)

                        ti, at.nelems = idaapi.tinfo_t(), size
                        if not ti.create_array(at):
                            raise E.DisassemblerError(u"{:s}.iterate({:#x}) : Unable to create an array of the required number of bytes ({:d}).".format('.'.join([__name__, cls.__name__]), ea, size))

                        # Use the location to try and find the member that it points to.
                        try:
                            item = fr.members.by(Flocation(location))
                        except (E.MemberNotFoundError, E.OutOfBoundsError):
                            if not operator.contains(tilookup, 8 * size) or not ti.deserialize(None, bytes(bytearray([tilookup[8 * size]])), None):
                                raise E.DisassemblerError(u"{:s}.iterate({:#x}) : Unable to create a type of the required number of bytes ({:d}).".format('.'.join([__name__, cls.__name__]), ea, size))
                            item, ti, name = location, ti, aname
                        else:
                            item, ti, name = (item, item.typeinfo, item.name) if item.offset == location.offset else (location, ti, aname)
                        yield item, ti, name

                    # That was all the arguments we found in the frame...which means, we're done.
                return

            # If we got here, then we have type information that we can grab out
            # of the given address. Once we have it, rip the details out o it.
            tinfo = interface.function.typeinfo(ea)
            _, ftd = interface.tinfo.function_details(ea, tinfo)

            # Now we just need to iterate through our parameters collecting the
            # raw location information for all of them. We preserve the type
            # information in case we're unable to find the argument in a member.
            items = []
            for index in builtins.range(ftd.size()):
                arg, loc = ftd[index], ftd[index].argloc
                items.append((index, utils.string.of(arg.name), arg.type, interface.tinfo.location_raw(loc)))

            # Last thing that we need to do is to extract each location and
            # figure out whether we return it as a register or an actual member.
            fr = None if rt else frame(ea) if idaapi.get_frame(ea) else None
            for index, name, ti, location in items:
                atype, ainfo = location
                loc = interface.tinfo.location(ti.get_size(), instruction.architecture, atype, ainfo)

                # If it's a location, then we can just add the register size to
                # find where the member is located at. This becomes our result
                # if we have a frame. Otherwise we return the location.
                if isinstance(loc, interface.location_t):
                    aname = name or interface.tuplename('arg', loc.offset)
                    try:
                        item = fr.members.by(loc) if fr else loc
                    except (E.MemberNotFoundError, E.OutOfBoundsError):
                        item, name = loc, aname
                    else:
                        name = item.name if fr else aname
                    finally:
                        yield item, ti, name or aname

                # If it's a tuple, then we check if it contains any registers
                # so that way we can process them if necessary. If its a register
                # offset where its second item is an integer and it's zero, then
                # we can simply exclude the offset from our results.
                elif isinstance(loc, types.tuple) and any(isinstance(item, interface.register_t) for item in loc):
                    reg, offset = loc
                    yield loc if offset else reg, ti, name

                # Otherwise, it's one of the custom locations that we don't
                # support. So we can just return it as we received it.
                else:
                    yield loc, ti, name
                continue
            return

        @utils.multicase()
        @classmethod
        def registers(cls):
            '''Return the register information associated with the arguments of the current function.'''
            return cls.registers(ui.current.address())
        @utils.multicase(func=(idaapi.func_t, types.integer))
        @classmethod
        def registers(cls, func):
            '''Return the register information associated with the arguments of the function `func`.'''
            result = []
            for reg, ti, name in cls.iterate(func):
                result.append(reg) if any([isinstance(reg, interface.register_t), isinstance(reg, types.tuple) and all(isinstance(item, interface.register_t) for item in reg)]) else None
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
            max = structure.size(get_frameid(fn))
            total = frame.lvars.size(fn) + frame.regs.size(fn)
            return max - total
    args = arg = arguments  # XXX: ns alias

    class lvars(object):
        """
        This namespace provides information about the local variables
        defined within a function's frame.

        Some ways to get this information can be::

            > print( function.frame.lvars.size() )

        """
        @utils.multicase()
        def __new__(cls):
            '''Yield the `(offset, name, size)` of each local variable relative to the stack pointer for the current function.'''
            return cls(ui.current.address())
        @utils.multicase(func=(idaapi.func_t, types.integer))
        def __new__(cls, func):
            '''Yield the `(offset, name, size)` of each local variable relative to the stack pointer for the function `func`.'''
            fn = interface.function.by(func)

            # figure out the frame
            fr = idaapi.get_frame(fn)
            if fr is None:  # unable to figure out arguments
                raise E.MissingTypeOrAttribute(u"{:s}({:#x}) : Unable to get the function frame.".format('.'.join([__name__, cls.__name__]), interface.range.start(fn)))

            results = []
            for off, size, content in structure.fragment(fr.id, 0, fn.frsize):
                results.append((off - idaapi.frame_off_savregs(fn), content.get('__name__', None), size))
            return results

        @utils.multicase()
        @classmethod
        def size(cls):
            '''Returns the size of the local variables for the current function.'''
            return cls.size(ui.current.function())
        @utils.multicase(func=(idaapi.func_t, types.integer))
        @classmethod
        def size(cls, func):
            '''Returns the size of the local variables for the function `func`.'''
            fn = interface.function.by(func)
            return fn.frsize
    vars = lvars    # XXX: ns alias

    class regs(object):
        """
        This namespace provides information about the registers that
        are saved when a function constructs its frame.

        An example of using this namespace::

            > print( function.frame.regs.size(ea) )

        """

        @utils.multicase()
        def __new__(cls):
            '''Yield the `(offset, name, size)` of each saved register relative to the stack pointer of the current function.'''
            return cls(ui.current.address())
        @utils.multicase(func=(idaapi.func_t, types.integer))
        def __new__(cls, func):
            '''Yield the `(offset, name, size)` of each saved register relative to the stack pointer of the function `func`.'''
            fn = interface.function.by(func)

            # figure out the frame
            fr = idaapi.get_frame(fn)
            if fr is None:  # unable to figure out arguments
                raise E.MissingTypeOrAttribute(u"{:s}({:#x}) : Unable to get the function frame.".format('.'.join([__name__, cls.__name__]), interface.range.start(fn)))

            results, regsize, delta = [], sum([fn.frregs, idaapi.get_frame_retsize(fn)]), idaapi.frame_off_args(fn)
            iterable = structure.fragment(fr.id, idaapi.frame_off_savregs(fn), regsize) if regsize else []
            for off, size, content in iterable:
                results.append((off - delta, content.get('__name__', None), size))
            return results

        @utils.multicase()
        @classmethod
        def size(cls):
            '''Returns the number of bytes occupied by the saved registers in the current function.'''
            return cls.size(ui.current.function())
        @utils.multicase(func=(idaapi.func_t, types.integer))
        @classmethod
        def size(cls, func):
            '''Returns the number of bytes occupied by the saved registers for the function `func`.'''
            fn = interface.function.by(func)
            return fn.frregs + idaapi.get_frame_retsize(fn)

get_frameid = utils.alias(frame.id, 'frame')
get_args_size = utils.alias(frame.args.size, 'frame.args')
get_vars_size = utils.alias(frame.lvars.size, 'frame.lvars')
get_regs_size = utils.alias(frame.regs.size, 'frame.regs')
get_spdelta = spdelta = utils.alias(frame.delta, 'frame')

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
    return internal.comment.contents.name(item, target=item)
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
def select(tag, *included, **boolean):
    '''Query the contents of the current function for the given `tag` or any others that should be `included`.'''
    res = {tag} | {item for item in included}
    boolean['included'] = {item for item in boolean.get('included', [])} | res
    return select(ui.current.function(), **boolean)
@utils.multicase(func=(idaapi.func_t, types.integer), tag=types.string)
@utils.string.decorate_arguments('tag', 'And', 'Or', 'require', 'requires', 'required', 'include', 'includes', 'included')
def select(func, tag, *included, **boolean):
    '''Query the contents of the function `func` for the given `tag` or any others that should be `included`.'''
    res = {tag} | {item for item in included}
    boolean['included'] = {item for item in boolean.get('included', [])} | res
    return select(func, **boolean)
@utils.multicase(func=(idaapi.func_t, types.integer), tags=types.unordered)
@utils.string.decorate_arguments('tags', 'And', 'Or', 'require', 'requires', 'required', 'include', 'includes', 'included')
def select(func, tags, *included, **boolean):
    '''Query the contents of the function `func` for the given `tags` or any others that should be `included`.'''
    res = {item for item in tags} | {item for item in included}
    boolean['included'] = {item for item in boolean.get('included', [])} | res
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

    # If nothing specific was queried, then yield all tags that are available.
    if not boolean:
        for ea in internal.comment.contents.address(interface.range.start(target), target=interface.range.start(target)):
            ui.navigation.analyze(ea)
            address = internal.tags.address.get(ea)
            if address: yield ea, address
        return

    # Collect the tagnames being queried as specified by the user.
    included, required = ({item for item in itertools.chain(*(boolean.get(B, []) for B in Bs))} for Bs in [['Or', 'include', 'included', 'includes'], ['And', 'require', 'required', 'requires']])

    # Walk through every tagged address and cross-check it against the query.
    for ea in internal.comment.contents.address(interface.range.start(target), target=interface.range.start(target)):
        ui.navigation.analyze(ea)
        collected, address = {}, internal.tags.address.get(ea)

        # included is the equivalent of Or(|) and yields the address if any of the tagnames are used.
        collected.update({key : value for key, value in address.items() if key in included})

        # required is the equivalent of And(&) which yields the addrss only if it uses all of the specified tagnames.
        if required:
            if required & six.viewkeys(address) == required:
                collected.update({key : value for key, value in address.items() if key in required})
            else: continue

        # If anything was collected (matched), then yield the address and the matching tags.
        if collected: yield ea, collected
    return

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
        MANGLED_CODE, MANGLED_DATA, MANGLED_UNKNOWN = getattr(idaapi, 'MANGLED_CODE', 0), getattr(idaapi, 'MANGLED_DATA', 1), getattr(idaapi, 'MANGLED_UNKNOWN', 2)
        Fmangled_type = idaapi.get_mangled_name_type if hasattr(idaapi, 'get_mangled_name_type') else utils.fcompose(utils.frpartial(idaapi.demangle_name, 0), utils.fcondition(operator.truth)(0, MANGLED_UNKNOWN))
        MNG_NODEFINIT, MNG_NOPTRTYP, MNG_LONG_FORM = getattr(idaapi, 'MNG_NODEFINIT', 8), getattr(idaapi, 'MNG_NOPTRTYP', 7), getattr(idaapi, 'MNG_LONG_FORM', 0x6400007)
        parseflags = functools.reduce(operator.or_, [idaapi.PT_SIL, idaapi.PT_VAR, idaapi.PT_LOWER, idaapi.PT_NDC])

        # Figure out what we're actually going to be applying the type information to,
        # and figure out what its real name is so that we can mangle it if necessary.
        rt, ea = interface.addressOfRuntimeOrStatic(func)

        fname, mangled = interface.function.name(ea), interface.name.get(ea) if rt else utils.string.of(idaapi.get_func_name(ea))
        if fname and Fmangled_type(utils.string.to(mangled)) != MANGLED_UNKNOWN:
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
        return cls.flags(ui.current.function())
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
        fn = interface.function.by(func)
        return interface.function.flags(fn, mask)
    @utils.multicase(func=(idaapi.func_t, types.integer), mask=types.integer, integer=(types.bool, types.integer))
    @classmethod
    def flags(cls, func, mask, integer):
        '''Set the flags for the function `func` selected by the specified `mask` to the provided `integer`.'''
        fn = interface.function.by(func)
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
        fn = interface.function.by(func)
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
        ok = isinstance(func, idaapi.func_t) or idaapi.get_func(func)
        return True if ok and cls.flags(func, idaapi.FUNC_FRAME) else False
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
        '''Return if the current function returns.'''
        return cls.leave(ui.current.function())
    @utils.multicase(func=(idaapi.func_t, types.integer))
    @classmethod
    def leave(cls, func):
        '''Return if the function `func` returns.'''
        fn = interface.function.by(func)
        if fn.flags & idaapi.FUNC_NORET_PENDING == idaapi.FUNC_NORET_PENDING:
            logging.warning(u"{:s}.leave({:s}) : Analysis for function return is still pending due to the `{:s}` flag being set.".format('.'.join([__name__, cls.__name__]), ("{:#x}" if isinstance(func, types.integer) else "{!r}").format(func), '.'.join(['idaapi', 'FUNC_NORET_PENDING'])))
        return not (fn.flags & idaapi.FUNC_NORET == idaapi.FUNC_NORET)
    has_return = returns = utils.alias(leave, 'type')

    @utils.multicase()
    @classmethod
    def library(cls):
        '''Return a boolean describing whether the current function is considered a library function.'''
        return cls.library(ui.current.function())
    @utils.multicase(func=(idaapi.func_t, types.integer))
    @classmethod
    def library(cls, func):
        '''Return a boolean describing whether the function `func` is considered a library function.'''
        ok = isinstance(func, idaapi.func_t) or idaapi.get_func(func)
        return True if ok and cls.flags(func, idaapi.FUNC_LIB) else False
    @utils.multicase(func=(idaapi.func_t, types.integer))
    @classmethod
    def library(cls, func, boolean):
        '''Modify the attributes of the function `func` to set it as a library function depending on the value of `boolean`.'''
        return cls.flags(func, idaapi.FUNC_LIB, -1 if boolean else 0) == idaapi.FUNC_LIB
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
        ok = isinstance(func, idaapi.func_t) or idaapi.get_func(func)
        return True if ok and cls.flags(func, idaapi.FUNC_THUNK) else False
    @utils.multicase(func=(idaapi.func_t, types.integer))
    @classmethod
    def thunk(cls, func, boolean):
        '''Modify the attributes of the function `func` to set it as a code thunk depending on the value of `boolean`.'''
        return cls.flags(func, idaapi.FUNC_THUNK, -1 if boolean else 0) == idaapi.FUNC_THUNK
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
        ok = isinstance(func, idaapi.func_t) or idaapi.get_func(func)
        return True if ok and cls.flags(func, idaapi.FUNC_FAR | idaapi.FUNC_USERFAR) else False
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
        ok = isinstance(func, idaapi.func_t) or idaapi.get_func(func)
        return True if ok and cls.flags(func, FUNC_STATICDEF) else False
    @utils.multicase(func=(idaapi.func_t, types.integer))
    @classmethod
    def static(cls, func, boolean):
        '''Modify the attributes of the function `func` to set it as a static function depending on the value of `boolean`.'''
        FUNC_STATICDEF = idaapi.FUNC_STATICDEF if hasattr(idaapi, 'FUNC_STATICDEF') else idaapi.FUNC_STATIC
        return cls.flags(func, FUNC_STATICDEF, -1 if boolean else 0) == FUNC_STATICDEF
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
        ok = isinstance(func, idaapi.func_t) or idaapi.get_func(func)
        return True if ok and cls.flags(func, idaapi.FUNC_HIDDEN) else False
    @utils.multicase(func=(idaapi.func_t, types.integer))
    @classmethod
    def hidden(cls, func, boolean):
        '''Modify the attributes of the function `func` to set it as a hidden function depending on the value of `boolean`.'''
        return cls.flags(func, idaapi.FUNC_HIDDEN, -1 if boolean else 0) == idaapi.FUNC_HIDDEN
    is_hidden = utils.alias(hidden, 'type')

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
        ok = isinstance(func, idaapi.func_t) or idaapi.get_func(func)
        return True if ok and cls.flags(func, FUNC_OUTLINE) else False
    @utils.multicase(func=(idaapi.func_t, types.integer))
    @classmethod
    def outline(cls, func, boolean):
        '''Modify the attributes of the function `func` to set it as an outlined function depending on the value of `boolean`.'''
        FUNC_OUTLINE = getattr(idaapi, 'FUNC_OUTLINE', 0x20000)
        return cls.flags(func, FUNC_OUTLINE, -1 if boolean else 0) == idaapi.FUNC_OUTLINE
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
        '''Set the calling convention used by the prototype for the current function to the string specified by `convention`.'''
        return cls.convention(ui.current.address(), convention)
    @utils.multicase(func=(idaapi.func_t, types.integer))
    @classmethod
    def convention(cls, func):
        '''Return the calling convention for the function `func` as an integer that corresponds to one of the ``idaapi.CM_CC_*`` constants.'''
        _, ea = interface.addressOfRuntimeOrStatic(func)

        # Grab the type information for the specified function, guessing it if necessary.
        ti = interface.function.typeinfo(func)

        # Now we can just grab the function details for this type, use it to extract
        # the convention and the spoiled count, and then return what we found.
        _, ftd = interface.tinfo.function_details(ea, ti)
        result, spoiled_count = ftd.cc & idaapi.CM_CC_MASK, ftd.cc & ~idaapi.CM_CC_MASK
        return result
    @utils.multicase(func=(idaapi.func_t, types.integer), convention=(types.string, types.none, types.ellipsis))
    @classmethod
    def convention(cls, func, convention):
        '''Set the calling convention used by the prototype for the function `func` to the string specified by `convention`.'''
        cc = internal.declaration.convention.get(convention)
        return cls.convention(func, cc)
    @utils.multicase(func=(idaapi.func_t, types.integer), convention=types.integer)
    @classmethod
    def convention(cls, func, convention):
        '''Set the calling convention used by the prototype for the function `func` to the specified `convention`.'''
        _, ea = interface.addressOfRuntimeOrStatic(func)

        # Grab the type information from the resolved address, guessing if at all necessary.
        ti = interface.function.typeinfo(func)

        # Now we just need to create the strpath.update_function_details
        # coroutine. Our first result will contain the function details
        # for us to tinker with.
        updater = interface.tinfo.update_function_details(ea, ti)
        _, ftd = builtins.next(updater)

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
    cc = utils.alias(convention, 'type')

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
            '''Return the result type for the current function as an ``idaapi.tinfo_t``.'''
            # we avoid ui.current.function() so that we can also act on function pointers.
            return cls(ui.current.address())
        @utils.multicase(info=(idaapi.tinfo_t, types.string))
        def __new__(cls, info):
            '''Modify the result type for the current function to the type information provided as an ``idaapi.tinfo_t`` provided in `info`.'''
            return cls(ui.current.address(), info)
        @utils.multicase(func=(idaapi.func_t, types.integer))
        def __new__(cls, func):
            '''Return the result type for the function `func` as an ``idaapi.tinfo_t``.'''
            try:
                _, ea = internal.interface.addressOfRuntimeOrStatic(func)

            # If we couldn't resolve the function, then consider our parameter
            # as some type information that we're going to apply to the current one.
            except E.FunctionNotFoundError:
                return cls(ui.current.address(), func)

            # The user gave us a function to try out, so we'll try and grab the
            # type information from the address we resolved.
            else:
                ti = type(ea)

            # Now we can grab our function details and then return the type.
            _, ftd = interface.tinfo.function_details(ea, ti)
            return ftd.rettype
        @utils.multicase(func=(idaapi.func_t, types.integer), info=types.string)
        @utils.string.decorate_arguments('info')
        def __new__(cls, func, info):
            '''Modify the result type for the function `func` to the type information provided as a string in `info`.'''

            # FIXME: figure out the proper way to parse a type instead of as a declaration
            tinfo = interface.tinfo.parse(None, info, idaapi.PT_SIL)
            if tinfo is None:
                raise E.InvalidTypeOrValueError(u"{:s}.result({!r}, {!r}) : Unable to parse the provided type information ({!r}).".format('.'.join([__name__, cls.__name__]), func, info, info))
            return cls(func, tinfo)
        @utils.multicase(func=(idaapi.func_t, types.integer), info=idaapi.tinfo_t)
        def __new__(cls, func, info):
            '''Modify the result type for the function `func` to the type information provided as an ``idaapi.tinfo_t`` in `info`.'''
            _, ea = interface.addressOfRuntimeOrStatic(func)

            # Grab the function type information that we plan on updating.
            ti = interface.function.typeinfo(func)

            # Now we can create an updater, and grab the details out of it.
            updater = interface.tinfo.update_function_details(ea, ti)
            _, ftd = builtins.next(updater)

            # From this, we'll trade the return type with the one the user gave us,
            # and then send it back to the updater to write it to the address.
            result, ftd.rettype = ftd.rettype, info
            updater.send(ftd), updater.close()

            # That was it and we only need to return the previous value.
            return result

        @utils.multicase()
        @classmethod
        def storage(cls):
            '''Return the storage location of the result belonging to the current function.'''
            return cls.storage(ui.current.address())
        @utils.multicase(func=(idaapi.func_t, types.integer))
        @classmethod
        def storage(cls, func):
            '''Return the storage location of the result belonging to the function `func`.'''
            _, ea = internal.interface.addressOfRuntimeOrStatic(func)
            ti = type(ea)

            # Grab the function details, rip the result type and location out of them.
            _, ftd = interface.tinfo.function_details(ea, ti)
            tinfo, location = ftd.rettype, ftd.retloc
            locinfo = interface.tinfo.location_raw(location)

            # Get the location out of it, and then figure out how to return it.
            result = interface.tinfo.location(tinfo.get_size(), instruction.architecture, *locinfo)
            if isinstance(result, types.tuple) and any(isinstance(item, interface.register_t) for item in result):
                reg, offset = result
                return result if offset else reg
            return result

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
            '''Return the type information for the parameter at the specified `index` of the current function.'''
            return cls(ui.current.address(), index)
        @utils.multicase(index=types.integer, info=(types.string, idaapi.tinfo_t))
        def __new__(cls, index, info):
            '''Modify the type information for the parameter at the specified `index` of the current function to `info`.'''
            return cls(ui.current.address(), index, info)
        @utils.multicase(func=(idaapi.func_t, types.integer), index=types.integer)
        def __new__(cls, func, index):
            '''Return the type information for the parameter at the specified `index` of the function `func`.'''
            _, ea = internal.interface.addressOfRuntimeOrStatic(func)
            ti = type(ea)

            # Use the address and tinfo to grab the details containing our arguments,
            # and then check that the index is within its boundaries.
            _, ftd = interface.tinfo.function_details(ea, ti)
            if not (0 <= index < ftd.size()):
                raise E.InvalidTypeOrValueError(u"{:s}({:#x}, {:d}) : The provided index ({:d}) is not within the range of the number of arguments ({:d}) for the specified function ({:#x}).".format('.'.join([__name__, cls.__name__]), ea, index, index, ftd.size(), ea))

            # Now we can grab the argument using the index we were given and return its type.
            result = ftd[index]
            return result.type
        @utils.multicase(func=(idaapi.func_t, types.integer), index=types.integer, info=idaapi.tinfo_t)
        def __new__(cls, func, index, info):
            '''Modify the type information for the parameter at the specified `index` of the function `func` to `info`.'''
            _, ea = internal.interface.addressOfRuntimeOrStatic(func)
            ti = type(ea)

            # We're going to update the type information as the specified address.
            # So we'll use interface.tinfo.update_function_details to create an
            # updater...
            updater = interface.tinfo.update_function_details(ea, ti)

            # ...and then we grab the details out of it to check the user's index.
            _, ftd = builtins.next(updater)
            if not (0 <= index < ftd.size()):
                raise E.InvalidTypeOrValueError(u"{:s}({:#x}, {:d}, {!r}) : The provided index ({:d}) is not within the range of the number of arguments ({:d}) for the specified function ({:#x}).".format('.'.join([__name__, cls.__name__]), ea, index, "{!s}".format(info), index, ftd.size(), ea))

            # Now we can just trade their type with the argument at the given index.
            argument = ftd[index]
            result, argument.type = argument.type, info

            # Then we can send it back to our updater, and return the previous value.
            updater.send(ftd), updater.close()
            return result
        @utils.multicase(func=(idaapi.func_t, types.integer), index=types.integer, info=types.string)
        @utils.string.decorate_arguments('info')
        def __new__(cls, func, index, info):
            '''Modify the type information for the parameter at the specified `index` of the function `func` to the string in `info`.'''
            tinfo = interface.tinfo.parse(None, info, idaapi.PT_SIL)
            if tinfo is None:
                raise E.InvalidTypeOrValueError(u"{:s}({!r}, {:d}, {!r}) : Unable to parse the provided type information ({!r}).".format('.'.join([__name__, cls.__name__]), func, index, info, info))
            return cls(func, index, tinfo)

        @utils.multicase(index=types.integer)
        @classmethod
        def name(cls, index):
            '''Return the name of the parameter at the specified `index` in the current function.'''
            return cls.name(ui.current.address(), index)
        @utils.multicase(index=types.integer, none=types.none)
        @classmethod
        def name(cls, index, none):
            '''Remove the name from the parameter at the specified `index` in the current function.'''
            return cls.name(ui.current.address(), index, none)
        @utils.multicase(index=types.integer, string=types.string)
        @classmethod
        def name(cls, index, string, *suffix):
            '''Modify the name of the parameter at the specified `index` of the current function to `string`.'''
            return cls.name(ui.current.address(), index, string, *suffix)
        @utils.multicase(func=(idaapi.func_t, types.integer), index=types.integer)
        @classmethod
        def name(cls, func, index):
            '''Return the name of the parameter at the specified `index` in the function `func`.'''
            _, ea = internal.interface.addressOfRuntimeOrStatic(func)
            ti = type(ea)

            # Use the address and type to get the function details, and then check that
            # the user's index is within their boundaries to access the argument name.
            _, ftd = interface.tinfo.function_details(ea, ti)
            if not (0 <= index < ftd.size()):
                raise E.InvalidTypeOrValueError(u"{:s}.name({:#x}, {:d}) : The provided index ({:d}) is not within the range of the number of arguments ({:d}) for the specified function ({:#x}).".format('.'.join([__name__, 'type', cls.__name__]), ea, index, index, ftd.size(), ea))

            # Now we can grab the argument using the index we were given and return its name.
            result = ftd[index]
            return utils.string.of(result.name) or None
        @utils.multicase(func=(idaapi.func_t, types.integer), index=types.integer, none=types.none)
        @classmethod
        def name(cls, func, index, none):
            '''Remove the name from the parameter at the specified `index` in the function `func`.'''
            return cls.name(func, index, '')
        @utils.multicase(func=(idaapi.func_t, types.integer), index=types.integer, string=types.string)
        @classmethod
        @utils.string.decorate_arguments('string', 'suffix')
        def name(cls, func, index, string, *suffix):
            '''Modify the name of the parameter at the specified `index` of the function `func` to `string`.'''
            _, ea = internal.interface.addressOfRuntimeOrStatic(func)
            ti, name = type(ea), interface.tuplename(*itertools.chain([string], suffix))

            # Now we can just use the address and type to create an updater for
            # our function details. Grab the func_type_data_t from it and check
            # that the user's argument index is within its bounds.
            updater = interface.tinfo.update_function_details(ea, ti)
            _, ftd = builtins.next(updater)
            if not (0 <= index < ftd.size()):
                raise E.InvalidTypeOrValueError(u"{:s}.name({:#x}, {:d}, {!s}) : The provided index ({:d}) is not within the range of the number of arguments ({:d}) for the specified function ({:#x}).".format('.'.join([__name__, 'type', cls.__name__]), ea, index, utils.string.repr(name), index, ftd.size(), ea))

            # Only thing left to do is to trade the name the user gave us with
            # whatever was stored at the parameter index they specified.
            argument = ftd[index]
            result, argument.name = argument.name, utils.string.to(name)

            # Now we can send the whole thing back to the updater, close it,
            # and then return the previous result that was assigned.
            updater.send(ftd), updater.close()
            return result or None

        @utils.multicase(index=types.integer)
        @classmethod
        def storage(cls, index):
            '''Return the storage location of the parameter at the specified `index` in the current function.'''
            return cls.storage(ui.current.address(), index)
        @utils.multicase(func=(idaapi.func_t, types.integer), index=types.integer)
        @classmethod
        def storage(cls, func, index):
            '''Return the storage location of the parameter at the specified `index` in the function `func`.'''
            _, ea = internal.interface.addressOfRuntimeOrStatic(func)
            locations = [item for _, _, item in type.arguments.iterate(func)]

            # As always, check our bounds and raise an exception...cleanly.
            if not (0 <= index < len(locations)):
                raise E.InvalidTypeOrValueError(u"{:s}.storage({:#x}, {:d}) : The provided index ({:d}) is not within the range of the number of arguments ({:d}) for the specified function ({:#x}).".format('.'.join([__name__, 'type', cls.__name__]), ea, index, index, len(locations), ea))
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
            '''Remove the parameter at the specified `index` from the current function.'''
            return cls.remove(ui.current.address(), index)
        @utils.multicase(func=(idaapi.func_t, types.integer), index=types.integer)
        @classmethod
        def remove(cls, func, index):
            '''Remove the parameter at the specified `index` from the function `func`.'''
            _, ea = internal.interface.addressOfRuntimeOrStatic(func)
            updater = interface.tinfo.update_function_details(ea, type(ea))

            # Grab the type and the details and verify the index is valid before
            # collecting into a list that we'll use for modifying things.
            ti, ftd = builtins.next(updater)
            if not (0 <= index < ftd.size()):
                raise E.InvalidTypeOrValueError(u"{:s}.remove({:#x}, {:d}) : The provided index ({:d}) is not within the range of the number of arguments ({:d}) for the specified function ({:#x}).".format('.'.join([__name__, 'type', cls.__name__]), ea, index, index, ftd.size(), ea))
            items = [ftd[idx] for idx in builtins.range(ftd.size())]

            # Now we can safely modify out list, and pop out the funcarg_t from it.
            farg = items.pop(index)
            name, result, location, comment = utils.string.of(farg.name), farg.type, farg.argloc, farg.cmt

            # Instead of recreating the func_type_data_t, we'll reassign the
            # references back in, and then resize it afterwards.
            for idx, item in enumerate(items):
                ftd[idx] = item
            ftd.resize(len(items))

            # At this point we shouldn't have any references to anything that we
            # modified, and can send it back to update the prototype correctly.
            updater.send(ftd), updater.close()
            return result
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
            items = type.arguments.locations(ea)
            return items[index]

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
            '''Return the type information for each of the parameters belonging to the current function.'''
            return cls(ui.current.address())
        @utils.multicase(func=(idaapi.func_t, internal.types.integer))
        def __new__(cls, func):
            '''Return the type information for each of the parameters belonging to the function `func`.'''
            _, ea = internal.interface.addressOfRuntimeOrStatic(func)
            ti = type(ea)

            # Use the address and type to snag the details requested by the
            # caller, iterate through it, and then return each type as a list.
            _, ftd = interface.tinfo.function_details(ea, ti)
            iterable = (ftd[index] for index in builtins.range(ftd.size()))
            return [item.type for item in iterable]
        @utils.multicase(func=(idaapi.func_t, internal.types.integer), types=internal.types.ordered)
        def __new__(cls, func, types):
            '''Overwrite the type information for the parameters belonging to the function `func` with the provided list of `types`.'''
            _, ea = internal.interface.addressOfRuntimeOrStatic(func)
            updater = interface.tinfo.update_function_details(ea, type(ea))

            # Grab the type and parameters so we can capture all of the ones that will be replaced.
            ti, ftd = builtins.next(updater)

            # Iterate through all of the parameters capturing all of the state that we'll return.
            results = []
            for idx in builtins.range(ftd.size()):
                farg = ftd[idx]
                aname, atype, aloc, acmt = farg.name, farg.type, farg.argloc, farg.cmt
                results.append((aname, atype, aloc, acmt))

            # Now we should able to resize our details, and then update them with our input.
            ftd.resize(len(types))
            for index, item in enumerate(types):
                aname, ainfo = item if isinstance(item, internal.types.tuple) else ('', item)
                ftd[index].name, ftd[index].type = utils.string.to(aname), interface.tinfo.parse(None, ainfo, idaapi.PT_SIL) if isinstance(ainfo, internal.types.string) else ainfo
            updater.send(ftd), updater.close()

            # The very last thing we need to do is to return our results. Even though we collected
            # all their information for safety, we return just the types for simplicity.
            return [item for _, item, _, _ in results]

        @utils.multicase()
        @classmethod
        def count(cls):
            '''Return the number of parameters in the prototype for the current function.'''
            return cls.count(ui.current.address())
        @utils.multicase(func=(idaapi.func_t, internal.types.integer))
        @classmethod
        def count(cls, func):
            '''Return the number of parameters in the prototype of the function identified by `func`.'''
            ti = type(func)
            return ti.get_nargs()

        @utils.multicase()
        @classmethod
        def types(cls):
            '''Return the type information for each of the parameters belonging to the current function.'''
            return cls(ui.current.address())
        @utils.multicase(func=(idaapi.func_t, internal.types.integer))
        @classmethod
        def types(cls, func):
            '''Return the type information for each of the parameters belonging to the function `func`.'''
            return cls(func)
        @utils.multicase(func=(idaapi.func_t, internal.types.integer), types=internal.types.ordered)
        @classmethod
        def types(cls, func, types):
            '''Overwrite the type information for the parameters belonging to the function `func` with the provided list of `types`.'''
            return cls(func, types)
        type = utils.alias(types, 'type.arguments')

        @utils.multicase()
        @classmethod
        def names(cls):
            '''Return the names for each of the parameters belonging to the current function.'''
            return cls.names(ui.current.address())
        @utils.multicase(func=(idaapi.func_t, internal.types.integer))
        @classmethod
        def names(cls, func):
            '''Return the names for each of the parameters belonging to the function `func`.'''
            _, ea = internal.interface.addressOfRuntimeOrStatic(func)
            ti, ftd = interface.tinfo.function_details(ea, type(ea))

            # Iterate through the function details and return each name as a list.
            iterable = (ftd[index] for index in builtins.range(ftd.size()))
            return [utils.string.to(item.name) for item in iterable]
        @utils.multicase(names=internal.types.ordered)
        @classmethod
        def names(cls, names):
            '''Overwrite the names for the parameters belonging to the current function with the provided list of `names`.'''
            return cls.names(ui.current.address(), names)
        @utils.multicase(func=(idaapi.func_t, internal.types.integer), names=internal.types.ordered)
        @classmethod
        def names(cls, func, names):
            '''Overwrite the names for the parameters belonging to the function `func` with the provided list of `names`.'''
            _, ea = internal.interface.addressOfRuntimeOrStatic(func)

            # Grab the type and parameters so we can capture all of the ones that will be replaced.
            updater = interface.tinfo.update_function_details(ea, type(ea))
            ti, ftd = builtins.next(updater)

            # Force all of the names we were given into string that we can actually apply. Afterwards
            # we check to see if we were given any extra that we need to warn the user about.
            strings = [item for item in map("{!s}".format, names)]
            if strings[ftd.size():]:
                discarded = ["\"{:s}\"".format(utils.string.escape(item, '"')) for item in strings[ftd.size():]]
                logging.warning(u"{:s}.names({:#x}, {!r}) : Discarding {:d} additional name{:s} ({:s}) that {:s} given for the specified function which has only {:d} parameter{:s}.".format('.'.join([__name__, cls.__name__]), ea, names, len(discarded), '' if len(discarded) == 1 else 's', ', '.join(discarded), 'was' if len(discarded) == 1 else 'were', ftd.size(), '' if ftd.size() == 1 else 's'))

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
        name = utils.alias(names, 'type.arguments')

        @utils.multicase()
        @classmethod
        def iterate(cls):
            '''Yield the `(name, type, storage)` of each of the parameters belonging to the current function.'''
            return cls.iterate(ui.current.address())
        @utils.multicase(func=(idaapi.func_t, internal.types.integer))
        @classmethod
        def iterate(cls, func):
            '''Yield the `(name, type, storage)` of each of the parameters belonging to the function `func`.'''
            _, ea = internal.interface.addressOfRuntimeOrStatic(func)
            ti = type(ea)

            # This should be easy, as we only need to grab the details from the type.
            _, ftd = interface.tinfo.function_details(ea, ti)

            # Then we can just iterate through them and grab their raw values.
            items = []
            for index in builtins.range(ftd.size()):
                loc, name, ti = ftd[index].argloc, ftd[index].name, ftd[index].type
                locinfo = interface.tinfo.location_raw(loc)
                items.append((utils.string.of(name), ti, locinfo))

            # Now we can iterate through each of these items safely, process them,
            # and then yield each individual item to the caller.
            for index, item in enumerate(items):
                name, ti, storage = item
                ltype, linfo = storage
                result = interface.tinfo.location(ti.get_size(), instruction.architecture, ltype, linfo)

                # Check to see if we got an error. We do this with a hack, by
                # doing an identity check on what was returned.
                if result is linfo:
                    ltype_table = {getattr(idaapi, attribute) : attribute for attribute in dir(idaapi) if attribute.startswith('ALOC_')}
                    ltype_s = ltype_table.get(ltype, '')
                    logging.warning(u"{:s}.iterate({:#x}) : Unable to handle the unsupported type {:s}({:#x}) for argument at index {:d}{:s}{:s}.".format('.'.join([__name__, cls.__name__]), ea, ltype_s, ltype, index, " with the name \"{:s}\"".format(utils.string.escape(name, '"')) if name else '', " of the type {!s}".format(ti) if ti.is_well_defined() else ''))

                # Now we can yield our result that we determined for each parameter.
                yield name, ti, result
            return

        @utils.multicase()
        @classmethod
        def registers(cls):
            '''Return the registers for each of the parameters belonging to the current function.'''
            return cls.registers(ui.current.address())
        @utils.multicase(func=(idaapi.func_t, internal.types.integer))
        @classmethod
        def registers(cls, func):
            '''Return the registers for each of the parameters belonging to the function `func`.'''
            result = []
            for _, _, loc in cls.iterate(func):
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
            '''Return the storage location for each of the parameters belonging to the current function.'''
            return cls.storage(ui.current.address())
        @utils.multicase(func=(idaapi.func_t, internal.types.integer))
        @classmethod
        def storage(cls, func):
            '''Return the storage locations for each of the parameters belonging to the function `func`.'''
            iterable = (location for _, _, location in cls.iterate(func))
            result = []
            for _, _, item in cls.iterate(func):
                if isinstance(item, internal.types.tuple) and isinstance(item[1], internal.types.integer):
                    register, offset = item
                    result.append(item if offset else register)
                else:
                    result.append(item)
                continue
            return result

        @utils.multicase(info=(internal.types.string, idaapi.tinfo_t))
        @classmethod
        def add(cls, info):
            '''Add the provided type information in `info` as another parameter to the current function.'''
            return cls.add(ui.current.address(), info, '')
        @utils.multicase(func=(idaapi.func_t, internal.types.integer), info=(internal.types.string, idaapi.tinfo_t))
        @classmethod
        def add(cls, func, info):
            '''Add the provided type information in `info` as another parameter to the function `func`.'''
            return cls.add(func, info, '')
        @utils.multicase(func=(idaapi.func_t, internal.types.integer), info=(internal.types.string, idaapi.tinfo_t), name=internal.types.string)
        @classmethod
        @utils.string.decorate_arguments('name', 'suffix')
        def add(cls, func, info, name, *suffix):
            '''Add the provided type information in `info` with the given `name` as another parameter to the function `func`.'''
            _, ea = internal.interface.addressOfRuntimeOrStatic(func)
            updater = interface.tinfo.update_function_details(ea, type(ea))

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
        append = utils.alias(add, 'type.arguments')

        @utils.multicase()
        @classmethod
        def locations(cls):
            '''Return the address of each of the parameters being passed to the function referenced at the current address.'''
            return cls.locations(ui.current.address())
        @utils.multicase(ea=internal.types.integer)
        @classmethod
        def locations(cls, ea):
            '''Return the address of each of the parameters being passed to the function referenced at address `ea`.'''
            if not (interface.xref.has_code(ea, descend=True) and interface.instruction.is_call(ea)):
                raise E.InvalidTypeOrValueError(u"{:s}.arguments({:#x}) : Unable to return any parameters as the provided address ({:#x}) {:s} code references.".format('.'.join([__name__, 'type', cls.__name__]), ea, ea, 'does not have any' if interface.instruction.is_call(ea) else 'is not a call instruction with'))
            items = idaapi.get_arg_addrs(ea)
            return [] if items is None else [ea for ea in items]
        @utils.multicase(func=(idaapi.func_t, internal.types.integer), ea=internal.types.integer)
        @classmethod
        def locations(cls, func, ea):
            '''Return the address of each of the parameters for the function `func` that are being passed to the function referenced at address `ea`.'''
            refs = {ref for ref in cls.up(func)}
            if ea not in refs:
                logging.warning(u"{:s}.arguments({!r}, {:#x}) : Ignoring the provided function ({:#x}) as the specified reference ({:#x}) is not referring to it.".format('.'.join([__name__, 'type', cls.__name__]), func, ea, address(func), ea))
            return cls.locations(ea)
        location = utils.alias(locations, 'type.arguments')

    args = parameters = arguments

t = type # XXX: ns alias
prototype = utils.alias(type, 'type')
convention = cc = utils.alias(type.convention, 'type')
result = type.result # XXX: ns alias
arguments = args = type.arguments   # XXX: ns alias
argument = arg = type.argument  # XXX: ns alias

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
        if not (interface.xref.has_code(ea, True) and interface.instruction.is_call(ea)):
            raise E.InvalidTypeOrValueError(u"{:s}.arguments({:#x}) : Unable to return any parameters as the given address ({:#x}) {:s} code references.".format('.'.join([__name__, cls.__name__]), ea, ea, 'does not have any' if interface.instruction.is_call(ea) else 'is not a call instruction with'))
        items = idaapi.get_arg_addrs(ea) or []
        return [(None if ea == idaapi.BADADDR else ea) for ea in items]
    args = utils.alias(arguments, 'xref')

x = xref    # XXX: ns alias
up, down = utils.alias(xref.up, 'xref'), utils.alias(xref.down, 'xref')
calls, branches = utils.alias(xref.calls, 'xref'), utils.alias(xref.branches, 'xref')
