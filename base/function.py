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

import functools, operator, itertools, types
import logging, string

import database, instruction, structure
import ui, internal
from internal import utils, interface, exceptions as E

import idaapi

## searching
@utils.multicase()
def by_address():
    '''Return the function at the current address.'''
    return by_address(ui.current.address())
@utils.multicase(ea=six.integer_types)
def by_address(ea):
    '''Return the function containing the address `ea`.'''
    ea = interface.address.within(ea)
    res = idaapi.get_func(ea)
    if res is None:
        raise E.FunctionNotFoundError(u"{:s}.by_address({:#x}) : Unable to locate function by address.".format(__name__, ea))
    return res
byaddress = utils.alias(by_address)

@utils.string.decorate_arguments('name')
def by_name(name):
    '''Return the function with the specified `name`.'''
    # convert the name into something friendly for IDA
    res = utils.string.to(name)

    # ask IDA to get its address
    ea = idaapi.get_name_ea(idaapi.BADADDR, res)
    if ea == idaapi.BADADDR:
        raise E.FunctionNotFoundError(u"{:s}.by_name({!r}) : Unable to locate function by name.".format(__name__, name))

    # now that we have its address, return the func_t
    res = idaapi.get_func(ea)
    if res is None:
        raise E.FunctionNotFoundError(u"{:s}.by_name({!r}) : Unable to locate function by address.".format(__name__, name))
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
@utils.multicase(ea=six.integer_types)
def by(ea):
    '''Return the function at the address `ea`.'''
    return by_address(ea)
@utils.multicase(name=six.string_types)
@utils.string.decorate_arguments('name')
def by(name):
    '''Return the function with the specified `name`.'''
    return by_name(name)
@utils.multicase(frame=idaapi.struc_t)
def by(frame):
    '''Return the function that owns the specified `frame`.'''
    if frame.props & idaapi.SF_FRAME:
        ea = idaapi.get_func_by_frame(frame.id)
        return by(ea)
    raise E.FunctionNotFoundError(u"{:s}.by({:#x}) : Unable to locate function using a structure that is not a frame.".format(__name__, frame.id))
@utils.multicase(frame=structure.structure_t)
def by(frame):
    '''Return the function that owns the specified `frame`.'''
    return by(frame.ptr)

# FIXME: implement a matcher class for func_t

@utils.multicase()
def offset():
    '''Return the offset from the base of the database for the current function.'''
    func = ui.current.function()
    return offset(func, 0)
@utils.multicase()
def offset(func):
    '''Return the offset from the base of the database for the function `func`.'''
    return offset(func, 0)
@utils.multicase(offset=six.integer_types)
def offset(func, offset):
    '''Return the offset from the base of the database for the function `func` and add the provided `offset` to it.'''
    ea = address(func)
    return database.address.offset(ea) + offset

## properties
@utils.multicase()
def comment(**repeatable):
    '''Return the comment for the current function.'''
    fn = ui.current.function()
    res = idaapi.get_func_cmt(fn, repeatable.get('repeatable', True))
    return utils.string.of(res)
@utils.multicase()
def comment(func, **repeatable):
    """Return the comment for the function `func`.

    If the bool `repeatable` is specified, then return the repeatable comment.
    """
    fn = by(func)
    res = idaapi.get_func_cmt(fn, repeatable.get('repeatable', True))
    return utils.string.of(res)
@utils.multicase(string=six.string_types)
@utils.string.decorate_arguments('string')
def comment(string, **repeatable):
    '''Set the comment for the current function to `string`.'''
    fn = ui.current.function()
    return comment(fn, string, **repeatable)
@utils.multicase(none=None.__class__)
def comment(none, **repeatable):
    '''Remove the comment for the current function.'''
    fn = ui.current.function()
    return comment(fn, none or '', **repeatable)
@utils.multicase(string=six.string_types)
@utils.string.decorate_arguments('string')
def comment(func, string, **repeatable):
    """Set the comment for the function `func` to `string`.

    If the bool `repeatable` is specified, then modify the repeatable comment.
    """
    fn = by(func)

    res, ok = comment(fn, **repeatable), idaapi.set_func_cmt(fn, utils.string.to(string), repeatable.get('repeatable', True))
    if not ok:
        raise E.DisassemblerError(u"{:s}.comment({:#x}, \"{:s}\"{:s}) : Unable to call `idaapi.set_func_cmt({:#x}, {!r}, {!s})`.".format(__name__, ea, utils.string.escape(string, '"'), u", {:s}".format(utils.string.kwargs(repeatable)) if repeatable else '', ea, utils.string.to(string), repeatable.get('repeatable', True)))
    return res
@utils.multicase(none=None.__class__)
def comment(func, none, **repeatable):
    """Remove the comment for the function `func`.

    If the bool `repeatable` is specified, then remove the repeatable comment.
    """
    return comment(func, none or '', **repeatable)

@utils.multicase()
def name():
    '''Return the name of the current function.'''
    return name(ui.current.address())
@utils.multicase()
def name(func):
    '''Return the name of the function `func`.'''
    get_name = functools.partial(idaapi.get_name, idaapi.BADADDR) if idaapi.__version__ < 7.0 else idaapi.get_name
    MANGLED_CODE, MANGLED_DATA, MANGLED_UNKNOWN = getattr(idaapi, 'MANGLED_CODE', 0), getattr(idaapi, 'MANGLED_DATA', 1), getattr(idaapi, 'MANGLED_UNKNOWN', 2)
    Fmangled_type = idaapi.get_mangled_name_type if hasattr(idaapi, 'get_mangled_name_type') else utils.fcompose(utils.frpartial(idaapi.demangle_name, 0), utils.fcondition(operator.truth)(0, MANGLED_UNKNOWN))
    MNG_LONG_FORM = getattr(idaapi, 'MNG_LONG_FORM', 0x6400007)

    # check to see if it's a runtime-linked function
    rt, ea = interface.addressOfRuntimeOrStatic(func)
    if rt:
        name = get_name(ea)
        mangled_name_type_t = Fmangled_type(name)
        return utils.string.of(name) if mangled_name_type_t == MANGLED_UNKNOWN else utils.string.of(idaapi.demangle_name(name, MNG_LONG_FORM))
        #return internal.declaration.demangle(res) if internal.declaration.mangledQ(res) else res
        #return internal.declaration.extract.fullname(internal.declaration.demangle(res)) if internal.declaration.mangledQ(res) else res

    # otherwise it's a regular function, so try and get its name in a couple of ways
    name = idaapi.get_func_name(ea)
    if not name: name = get_name(ea)
    if not name: name = idaapi.get_true_name(ea, ea) if idaapi.__version__ < 6.8 else idaapi.get_ea_name(ea, idaapi.GN_VISIBLE)

    # decode the string from IDA's UTF-8 and demangle it if we need to
    # XXX: how does demangling work with utf-8? this would be implementation specific, no?
    mangled_name_type_t = Fmangled_type(name)
    return utils.string.of(name) if mangled_name_type_t == MANGLED_UNKNOWN else utils.string.of(idaapi.demangle_name(name, MNG_LONG_FORM))
    #return internal.declaration.demangle(res) if internal.declaration.mangledQ(res) else res
    #return internal.declaration.extract.fullname(internal.declaration.demangle(res)) if internal.declaration.mangledQ(res) else res
    #return internal.declaration.extract.name(internal.declaration.demangle(res)) if internal.declaration.mangledQ(res) else res
@utils.multicase(none=None.__class__)
def name(none, **flags):
    '''Remove the custom-name from the current function.'''
    # we use ui.current.address() instead of ui.current.function()
    # in case the user might be hovering over an import table
    # function and wanting to rename that instead.
    return name(ui.current.address(), none or '', **flags)
@utils.multicase(packed=tuple)
def name(packed, **flags):
    '''Set the name of the current function to the given `packed` name.'''
    return name(ui.current.address(), *packed, **flags)
@utils.multicase(string=six.string_types)
@utils.string.decorate_arguments('string', 'suffix')
def name(string, *suffix, **flags):
    '''Set the name of the current function to `string`.'''
    return name(ui.current.address(), string, *suffix, **flags)
@utils.multicase(none=None.__class__)
def name(func, none, **flags):
    '''Remove the custom-name from the function `func`.'''
    return name(func, none or '', **flags)
@utils.multicase(packed=tuple)
def name(func, packed, **flags):
    '''Set the name of the function `func` to the given `packed` name.'''
    return name(func, *packed, **flags)
@utils.multicase(string=six.string_types)
@utils.string.decorate_arguments('string', 'suffix')
def name(func, string, *suffix, **flags):
    """Set the name of the function `func` to `string`.

    If `flags` is specified, then use the specified value as the flags.
    If the boolean `listed` is specified, then specify whether to add the label to the Names list or not.
    """

    # combine name with its suffix
    res = (string,) + suffix
    string = interface.tuplename(*res)

    # figure out if address is a runtime or static function
    rt, ea = interface.addressOfRuntimeOrStatic(func)

    # set the default flags that we'll use based on whether the listed parameter was set.
    res = idaapi.SN_NOWARN | (0 if flags.get('listed', idaapi.is_in_nlist(ea)) else idaapi.SN_NOLIST)

    # if it's a runtime-linked function, then it's not a public name.
    if rt:
        flags.setdefault('flags', res | idaapi.SN_NON_PUBLIC)

    # if it's a static function, then we need to preserve its flags.
    else:
        res |= idaapi.SN_PUBLIC if idaapi.is_public_name(ea) else idaapi.SN_NON_PUBLIC
        res |= idaapi.SN_WEAK if idaapi.is_weak_name(ea) else idaapi.SN_NON_WEAK
        flags.setdefault('flags', res)

    # FIXME: mangle the name and shuffle it into the prototype if possible
    return database.name(ea, string, **flags)

@utils.multicase()
def prototype():
    '''Return the prototype of the current function if it has one.'''
    # use ui.current.address() instead of ui.current.function() to deal with import table entries
    return prototype(ui.current.address())
@utils.multicase()
def prototype(func):
    '''Return the prototype of the function `func` if it has one.'''
    rt, ea = interface.addressOfRuntimeOrStatic(func)
    funcname = database.name(ea) or name(ea)
    try:
        decl = internal.declaration.function(ea)
        idx = decl.find('(')
        res = "{result:s} {name:s}{parameters:s}".format(result=decl[:idx], name=funcname, parameters=decl[idx:])

    except E.MissingTypeOrAttribute:
        if not internal.declaration.mangledQ(funcname):
            raise
        return internal.declaration.demangle(funcname)
    return res

@utils.multicase()
def bounds():
    '''Return a tuple containing the bounds of the first chunk of the current function.'''
    fn = ui.current.function()
    return interface.range.bounds(fn)
@utils.multicase()
def bounds(func):
    '''Return a tuple containing the bounds of the first chunk of the function `func`.'''
    try:
        fn = by(func)
    except E.ItemNotFoundError:
        raise E.FunctionNotFoundError(u"{:s}.bounds({!r}) : Unable to find function at the given location.".format(__name__, func))
    return interface.range.bounds(fn)
range = utils.alias(bounds)

@utils.multicase()
def color():
    '''Return the color (RGB) of the current function.'''
    return color(ui.current.function())
@utils.multicase()
def color(func):
    '''Return the color (RGB) of the function `func`.'''
    fn, DEFCOLOR = by(func), 0xffffffff
    b, r = (fn.color&0xff0000)>>16, fn.color&0x0000ff
    return None if fn.color == DEFCOLOR else (r<<16) | (fn.color&0x00ff00) | b
@utils.multicase(none=None.__class__)
def color(func, none):
    '''Remove the color for the function `func`.'''
    fn, DEFCOLOR = by(func), 0xffffffff
    res, fn.color = fn.color, DEFCOLOR
    if not idaapi.update_func(fn):
        F, ea = idaapi.update_func, interface.range.start(fn)
        raise E.DisassemblerError(u"{:s}.color({:#x}, {!s}) : Unable to clear the color of the function at {:#x} with `{:s}({:#x})`.".format(__name__, ea, none, ea, '.'.join([F.__module__ or '', F.__name__]), ea))
    b, r = (res&0xff0000)>>16, res&0x0000ff
    return None if res == DEFCOLOR else (r<<16) | (res&0x00ff00) | b
@utils.multicase(rgb=six.integer_types)
def color(func, rgb):
    '''Set the color (RGB) of the function `func` to `rgb`.'''
    r, b = (rgb&0xff0000)>>16, rgb&0x0000ff
    fn, DEFCOLOR = by(func), 0xffffffff
    res, fn.color = fn.color, (b<<16) | (rgb&0x00ff00) | r
    if not idaapi.update_func(fn):
        F, ea = idaapi.update_func, interface.range.start(fn)
        raise E.DisassemblerError(u"{:s}.color({:#x}, {:#x}) : Unable to set the color of the function at {:#x} with `{:s}({:#x})`.".format(__name__, ea, rgb, ea, '.'.join([F.__module__ or '', F.__name__]), ea))
    b, r = (res&0xff0000)>>16, res&0x0000ff
    return None if res == DEFCOLOR else (r<<16) | (res&0x00ff00) | b
@utils.multicase(none=None.__class__)
def color(none):
    '''Remove the color from the current function.'''
    return color(ui.current.function(), None)

@utils.multicase()
def address():
    '''Return the address of the entrypoint for the current function.'''
    try:
        res = ui.current.function()
    except E.ItemNotFoundError:
        raise E.FunctionNotFoundError(u"{:s}.address({:#x}) : Unable to locate the current function.".format(__name__, ui.current.address()))
    return interface.range.start(res)
@utils.multicase()
def address(func):
    '''Return the address for the entrypoint belonging to the function `func`.'''
    return address(func, 0)
@utils.multicase(offset=six.integer_types)
def address(func, offset):
    '''Return the address for the entrypoint belonging to the function `func` and add the provided `offset` to it.'''
    res = by(func)
    return interface.range.start(res) + offset
top = addr = utils.alias(address)

@utils.multicase()
def bottom():
    '''Return the exit-points of the current function.'''
    return bottom(ui.current.function())
@utils.multicase()
def bottom(func):
    '''Return the exit-points of the function `func`.'''
    fn = by(func)
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
@utils.multicase()
def marks(func):
    '''Return all the marks in the function `func`.'''
    fn, res = by(func), []
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
@utils.multicase(ea=six.integer_types)
def new(ea):
    '''Create a new function at the address specified by `ea`.'''
    start = interface.address.inside(ea)
    if not idaapi.add_func(start, idaapi.BADADDR):
        fullname = '.'.join([getattr(idaapi.add_func, attribute) for attribute in ['__module__', '__name__'] if hasattr(idaapi.add_func, attribute)])
        raise E.DisassemblerError(u"{:s}.new({:#x}) : Unable create a new function at the given address ({:#x}) with `{:s}`.".format(__name__, ea, start, fullname))
    ui.state.wait()
    return interface.range.bounds(by_address(start))
@utils.multicase(start=six.integer_types, end=six.integer_types)
def new(start, end):
    '''Create a new function from the address `start` until `end`.'''
    bounds = ea, stop = interface.bounds_t(*interface.address.within(start, end))
    if not idaapi.add_func(ea, stop):
        fullname = '.'.join([getattr(idaapi.add_func, attribute) for attribute in ['__module__', '__name__'] if hasattr(idaapi.add_func, attribute)])
        raise E.DisassemblerError(u"{:s}.new({:#x}, {:#x}) : Unable create a new function for the given boundaries ({:s}) with `{:s}`.".format(__name__, start, end, bounds, fullname))
    ui.state.wait()
    return interface.range.bounds(by_address(ea))
@utils.multicase(bounds=tuple)
def new(bounds):
    '''Create a new function using the specified `bounds`.'''
    start, end = bounds
    return new(start, end)

make = add = utils.alias(new)

@utils.multicase()
def remove():
    '''Remove the current function from the database.'''
    return remove(ui.current.function())
@utils.multicase()
def remove(func):
    '''Remove the function `func` from the database.'''
    fn = by(func)
    bounds = ea, _ = interface.range.bounds(fn)
    if not idaapi.del_func(ea):
        fullname = '.'.join([getattr(idaapi.del_func, attribute) for attribute in ['__module__', '__name__'] if hasattr(idaapi.del_func, attribute)])
        raise E.DisassemblerError(u"{:s}.remove({!r}) : Unable to delete the function at {:#x} ({:s}) with `{:s}`.".format(__name__, func, interface.range.start(fn), bounds, fullname))
    return bounds
@utils.multicase(bounds=tuple)
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
        '''Yield the bounds of each chunk within current function.'''
        return cls(ui.current.function())
    @utils.multicase()
    def __new__(cls, func):
        '''Yield the bounds of each chunk for the function `func`.'''
        fn = by(func)
        fci = idaapi.func_tail_iterator_t(fn, interface.range.start(fn))
        if not fci.main():
            raise E.DisassemblerError(u"{:s}.chunks({:#x}) : Unable to create an `idaapi.func_tail_iterator_t`.".format(__name__, interface.range.start(fn)))

        results = []
        while True:
            ch = fci.chunk()
            results.append(interface.range.bounds(ch))
            if not fci.next(): break
        return results

    @utils.multicase()
    @classmethod
    def iterate(cls):
        '''Iterate through all the instructions for each chunk in the current function.'''
        return cls.iterate(ui.current.function())
    @utils.multicase()
    @classmethod
    def iterate(cls, func):
        '''Iterate through all the instructions for each chunk in the function `func`.'''
        for start, end in cls(func):
            for ea in database.address.iterate(start, end):
                if database.type.is_code(ea):
                    yield ea
                continue
            continue
        return

    @utils.multicase()
    @classmethod
    def at(cls):
        '''Return an ``idaapi.range_t`` describing the bounds of the current function chunk.'''
        return cls.at(ui.current.address())
    @utils.multicase(ea=six.integer_types)
    @classmethod
    def at(cls, ea):
        '''Return an ``idaapi.range_t`` describing the bounds of the function chunk at the address `ea`.'''
        fn = by_address(ea)
        return cls.at(fn, ea)
    @utils.multicase(ea=six.integer_types)
    @classmethod
    def at(cls, func, ea):
        '''Return an ``idaapi.range_t`` describing the bounds of the function chunk belonging to `func` at the address `ea`.'''
        fn = by(func)
        for left, right in cls(fn):
            if left <= ea < right:
                area = interface.bounds_t(left, right)
                return area.range()
            continue
        raise E.AddressNotFoundError(u"{:s}.at({:#x}, {:#x}) : Unable to locate the chunk for the given address ({:#x}) in function {:#x}.".format('.'.join([__name__, cls.__name__]), interface.range.start(fn), ea, ea, interface.range.start(fn)))

    @utils.multicase()
    @classmethod
    def contains(cls):
        '''Returns True if the current function contains the current address in any of its chunks.'''
        return cls.contains(ui.current.function(), ui.current.address())
    @utils.multicase(ea=six.integer_types)
    @classmethod
    def contains(cls, ea):
        '''Returns True if the current function contains the address `ea` in any of its chunks.'''
        return cls.contains(ui.current.function(), ea)
    @utils.multicase(ea=six.integer_types)
    @classmethod
    def contains(cls, func, ea):
        '''Returns True if the function `func` contains the address `ea` in any of its chunks.'''
        try:
            fn, ea = by(func), interface.address.within(ea)

        # If the function is not found, or the address is out of bounds
        # then the address isn't contained in the function. Simple.
        except (E.FunctionNotFoundError, E.OutOfBoundsError):
            return False

        # If we didn't raise any exceptions, then grab all of the chunks
        # for the function that we determined.
        else:
            iterable = cls(fn)

        # Now we can just iterate through each chunk whilst checking the bounds.
        return any(start <= ea < end for start, end in iterable)

    @utils.multicase(reg=(six.string_types, interface.register_t))
    @classmethod
    def register(cls, reg, *regs, **modifiers):
        '''Yield each `(address, opnum, state)` within the current function that uses `reg` or any one of the registers in `regs`.'''
        return cls.register(ui.current.function(), reg, *regs, **modifiers)
    @utils.multicase(reg=(six.string_types, interface.register_t))
    @classmethod
    def register(cls, func, reg, *regs, **modifiers):
        """Yield each `(address, opnum, state)` within the function `func` that uses `reg` or any one of the registers in `regs`.

        If the keyword `write` is True, then only return the result if it's writing to the register.
        """
        iterops = interface.regmatch.modifier(**modifiers)
        uses_register = interface.regmatch.use( (reg,) + regs )

        for ea in cls.iterate(func):
            for opnum in iterops(ea):
                if uses_register(ea, opnum):
                    items = ea, opnum, instruction.op_state(ea, opnum)
                    yield interface.opref_t(*items)
            continue
        return

    @utils.multicase()
    @classmethod
    def points(cls):
        '''Yield the `(address, delta)` for each stack point where the delta changes in the current function.'''
        return cls.points(ui.current.function())
    @utils.multicase()
    @classmethod
    def points(cls, func):
        '''Yield the `(address, delta)` for each stack point where the delta changes in the function `func`.'''
        fn = by(func)
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
    @utils.multicase(ea=six.integer_types)
    def __new__(cls, ea):
        '''Return a tuple containing the bounds of the function chunk at the address `ea`.'''
        area = cls.at(ea, ea)
        return interface.range.bounds(area)

    @utils.multicase()
    @classmethod
    def owner(cls):
        '''Return the primary owner of the function chunk containing the current address.'''
        return cls.owner(ui.current.address())
    @utils.multicase(ea=six.integer_types)
    @classmethod
    def owner(cls, ea):
        '''Return the primary owner of the function chunk containing the address specified by `ea`.'''
        if within(ea):
            return next(item for item in cls.owners(ea))
        raise E.FunctionNotFoundError(u"{:s}.owner({:#x}) : Unable to locate a function at the specified address ({:#x}).".format('.'.join([__name__, cls.__name__]), ea, ea))
    @utils.multicase(bounds=tuple)
    @classmethod
    def owner(cls, bounds):
        '''Return the primary owner of the function chunk specified by `bounds`.'''
        ea, _ = bounds
        return cls.owner(ea)
    @utils.multicase(ea=six.integer_types)
    @classmethod
    def owner(cls, ea, func):
        '''Set the primary owner of the chunk at `ea` to the function `func`.'''
        ea, fn = interface.address.within(ea), by(func)
        result, ok = cls.owner(ea), idaapi.set_tail_owner(fn, ea)
        if not ok:
            fullname = '.'.join([getattr(idaapi.set_tail_owner, attribute) for attribute in ['__module__', '__name__'] if hasattr(idaapi.set_tail_owner, attribute)])
            raise E.DisassemblerError(u"{:s}.owner({#x}, {!r}) : Unable to modify the owner of the chunk at {:#x} to the given function ({:#x}) with `{:s}`.".format('.'.join([__name__, cls.__name__]), ea, func, ea, interface.range.start(fn), fullname))
        return result
    @utils.multicase(bounds=tuple)
    @classmethod
    def owner(cls, bounds, func):
        '''Set the primary owner of the chunk specified by `bounds` to the function `func`.'''
        ea, _ = bounds
        return cls.owner(ea, func)

    @utils.multicase()
    @classmethod
    def owners(cls):
        '''Yield each of the owners which have the current function chunk associated with it.'''
        ea = ui.current.address()
        return (item for item in cls.owners(ea))
    @utils.multicase(ea=six.integer_types)
    @classmethod
    def owners(cls, ea):
        '''Yield each of the owners which have the function chunk containing the address `ea` associated with it.'''
        res = idaapi.get_func(ea)

        # If we're not associated with a function, then we just leave. Otherwise,
        # we grab the function chunk for the requested address.
        if res is None:
            return

        # If we were unable to get the function chunk for the provided address,
        # then we can just return because there's nothing that owns it.
        ch = idaapi.get_fchunk(ea)
        if ch is None:
            raise internal.exceptions.DisassemblerError(u"{:s}.owners({:#x}) : Unable to read the chunk at {:#x} belonging to the function at {!s}.".format('.'.join([__name__, cls.__name__]), ea, ea, interface.range.bounds(res)))
        owner, bounds = map(interface.range.bounds, [res, ch])

        # If this is a function tail, then we need to iterate through the referers
        # for the chunk so that we can yield each address. Older versions of IDA
        # don't always give us an array, so we construct it if we don't get one.
        if ch.flags & idaapi.FUNC_TAIL:
            count, iterator = ch.refqty, idaapi.func_parent_iterator_t(ch)

            # Try and seek to the very first member of the iterator. This should
            # always succeed, so if it errors out then this is critical...but only
            # if our "refqty" is larger than 1. If it's less than 1, then we can
            # just warn the user..but we're gonna fall back to the func_t anyways.
            if not iterator.first():
                if count > 1:
                    raise internal.exceptions.DisassemblerError(u"{:s}.owners({:#x}) : Unable to seek to the first element of the `{:s}` for the function tail at {!s}.".format('.'.join([__name__, cls.__name__]), ea, iterator.__class__.__name__, bounds))

                # We should only have one single referrer to return. Just in case,
                # though, we return an empty list if our "refqty" is actually 0.
                logging.warning(u"{:s}.owners({:#x}) : Returning initial owner ({!s}) for the function tail at {!s} due to being unable to seek to the first element of the associated `{:s}`.".format('.'.join([__name__, cls.__name__]), ea, owner, bounds, iterator.__class__.__name__))
                referrers = [ea for ea, _ in ([owner] if count else [])]

            # Grab the first parent address. Afterwards we continue looping
            # whilst stashing parents in our list of referrers.
            else:
                referrers = [iterator.parent()]
                while iterator.next():
                    item = iterator.parent()
                    referrers.append(item)

            # That was easy enough, so now we just need to confirm that the
            # number of our referrers matches to the "refqty" of the chunk.
            if count != len(referrers):
                logging.warning(u"{:s}.owners({:#x}) : Expected to find {:d} referrer{:s} for the function tail at {!s}, but {:s}{:s} returned.".format('.'.join([__name__, cls.__name__]), ea, count, '' if count == 1 else 's', bounds, 'only ' if len(referrers) < count else '', "{:d} was".format(len(referrers)) if len(referrers) == 1 else "{:d} were".format(len(referrers))))

            # That was it, we just need to convert our results to an iterator.
            iterable = (ea for ea in referrers)

        # Otherwise, we just need to yield the function that owns this chunk.
        else:
            iterable = (ea for ea, _ in [owner])

        # We've collected all of our items, so iterate through what we've collected
        # and then yield them to the caller before returning.
        for ea in iterable:
            yield ea
        return

    @utils.multicase()
    @classmethod
    def iterate(cls):
        '''Iterate through all the instructions for the function chunk containing the current address.'''
        for ea in cls.iterate(ui.current.address()):
            yield ea
        return
    @utils.multicase(ea=six.integer_types)
    @classmethod
    def iterate(cls, ea):
        '''Iterate through all the instructions for the function chunk containing the address ``ea``.'''
        start, end = cls(ea)
        for ea in database.address.iterate(start, end):
            if database.type.is_code(ea):
                yield ea
            continue
        return

    @utils.multicase(reg=(six.string_types, interface.register_t))
    @classmethod
    def register(cls, reg, *regs, **modifiers):
        '''Yield each `(address, opnum, state)` within the function chunk containing the current address which uses `reg` or any one of the registers in `regs`.'''
        return cls.register(ui.current.address(), reg, *regs, **modifiers)
    @utils.multicase(reg=(six.string_types, interface.register_t))
    @classmethod
    def register(cls, ea, reg, *regs, **modifiers):
        """Yield each `(address, opnum, state)` within the function chunk containing the address `ea` which uses `reg` or any one of the registers in `regs`.

        If the keyword `write` is True, then only return the result if it's writing to the register.
        """
        iterops = interface.regmatch.modifier(**modifiers)
        uses_register = interface.regmatch.use( (reg,) + regs )

        for ea in cls.iterate(ea):
            for opnum in filter(functools.partial(uses_register, ea), iterops(ea)):
                items = ea, opnum, instruction.op_state(ea, opnum)
                yield interface.opref_t(*items)
            continue
        return

    @utils.multicase()
    @classmethod
    def points(cls):
        '''Yield the `(address, delta)` for each stack point where the delta changes in the current function chunk.'''
        return cls.points(ui.current.function(), ui.current.address())
    @utils.multicase(ea=six.integer_types)
    @classmethod
    def points(cls, ea):
        '''Yield the `(address, delta)` for each stack point where the delta changes in the chunk containing the address `ea`.'''
        fn = by_address(ea)
        return cls.points(fn, ea)
    @utils.multicase(ea=six.integer_types)
    @classmethod
    def points(cls, func, ea):
        '''Yield the `(address, delta)` for each stack point where the delta changes in the chunk containing the address `ea` belonging to the function `func`.'''
        ch = idaapi.get_fchunk(ea)

        # If we were unable to get the function chunk for the provided address,
        # then IDA didn't calculate any stack deltas for what was requested.
        if ch is None:
            return

        # If this is a function tail, then we need to get its owners so that we
        # can figure out which chunk will contain the address and calc'd delta.
        if ch.flags & idaapi.FUNC_TAIL:
            bounds, owners = interface.range.bounds(ch), (chunk for chunk in map(idaapi.get_fchunk, cls.owners(ea)) if chunk)

            # Now that we've grabbed each chunk, we need to filter each chunk
            # by its stack point so that we only grab the one referencing the
            # chunk the caller provided us.
            Fcontains = bounds.contains
            filtered = (chunk for chunk in owners if any(Fcontains(chunk.points[index].ea) for index in builtins.range(chunk.pntqty)))

            # We have a list of chunks that has been filtered for the specific
            # point within our chunk boundary. There really should be only one
            # chunk, but just in case we store them into a dict so that we can
            # use their address as a key to sort.
            items = itertools.chain(*(map(chunk.points.__getitem__, builtins.range(chunk.pntqty)) for chunk in filtered))
            available = {item.ea : item for item in items if Fcontains(item.ea)}

            # That was it. We have the sorted addresses of the points that we want,
            # and we need to just convert them back into an iterable so that we
            # can yield each point back to the caller.
            iterable = (available[ea] for ea in sorted(available))

        # Now we just need to iterate through all of the stack change points,
        # and then yield their address and the delta that was calculated.
        else:
            iterable = (ch.points[index] for index in builtins.range(ch.pntqty))

        # We have our iterator of points, so all we need to do is to unpack each
        # one and yield it to our caller.
        for point in iterable:
            yield point.ea, point.spd
        return
    stackpoints = utils.alias(points, 'chunk')

    @utils.multicase()
    @classmethod
    def at(cls):
        '''Return an ``idaapi.range_t`` describing the bounds of the current function chunk.'''
        return cls.at(ui.current.function(), ui.current.address())
    @utils.multicase(ea=six.integer_types)
    @classmethod
    def at(cls, ea):
        '''Return an ``idaapi.range_t`` describing the bounds of the function chunk at the address `ea`.'''
        fn = by_address(ea)
        return cls.at(fn, ea)
    @utils.multicase(ea=six.integer_types)
    @classmethod
    def at(cls, func, ea):
        '''Return an ``idaapi.range_t`` describing the bounds of the function chunk belonging to `func` at the address `ea`.'''
        return chunks.at(func, ea)

    @utils.multicase()
    @classmethod
    def top(cls):
        '''Return the top address of the chunk at the current address.'''
        left, _ = cls()
        return left
    @utils.multicase(ea=six.integer_types)
    @classmethod
    def top(cls, ea):
        '''Return the top address of the chunk at address `ea`.'''
        left, _ = cls(ea)
        return left
    @utils.multicase(ea=six.integer_types, address=six.integer_types)
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
        raise E.DisassemblerError(u"{:s}.top({:#x}, {:#x}) : Unable to modify the top of the specified chunk with `idaapi.set_func_start({:#x}, {:#x})` due to error ({:s}).".format('.'.join([__name__, cls.__name__]), ea, address, left, address, errors.get(result, "{:#x}".format(result))))

    @utils.multicase()
    @classmethod
    def bottom(cls):
        '''Return the bottom address of the chunk at the current address.'''
        _, right = cls()
        return right
    @utils.multicase(ea=six.integer_types)
    @classmethod
    def bottom(cls, ea):
        '''Return the bottom address of the chunk at address `ea`.'''
        _, right = cls(ea)
        return right
    @utils.multicase(ea=six.integer_types, address=six.integer_types)
    @classmethod
    def bottom(cls, ea, address):
        '''Change the bottom address of the chunk at address `ea` to the specified `address`.'''
        bounds = cls(ea)
        left, right = bounds
        if not idaapi.set_func_end(left, address):
            raise E.DisassemblerError(u"{:s}.bottom({:#x}, {:#x}) : Unable to modify the bottom of the specified chunk with `idaapi.set_func_end({:#x}, {:#x})`.".format('.'.join([__name__, cls.__name__]), ea, address, left, address))
        return right

    @utils.multicase()
    @classmethod
    def address(cls):
        '''Return the top address of the function chunk containing the current address.'''
        return cls.address(ui.current.address(), 0)
    @utils.multicase(ea=six.integer_types)
    @classmethod
    def address(cls, ea):
        '''Return the top address of the function chunk containing the address `ea`.'''
        return cls.address(ea, 0)
    @utils.multicase(ea=six.integer_types, offset=six.integer_types)
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
    @utils.multicase(ea=six.integer_types)
    @classmethod
    def offset(cls, ea):
        '''Return the offset from the base of the database for the function chunk containing the address `ea`.'''
        return cls.offset(ea, 0)
    @utils.multicase(ea=six.integer_types)
    @classmethod
    def offset(cls, ea, offset):
        '''Return the offset from the base of the database for the function chunk containing the address `ea` and add the provided `offset` to it.'''
        left, _ = cls(ea)
        return database.address.offset(left) + offset

    @utils.multicase(start=six.integer_types)
    @classmethod
    def add(cls, start):
        '''Add the chunk starting at the address `start` to the current function.'''
        return cls.add(ui.current.function(), start)
    @utils.multicase(bounds=tuple)
    @classmethod
    def add(cls, bounds):
        '''Add the chunk specified by `bounds` to the current function.'''
        return cls.add(ui.current.function(), bounds)
    @utils.multicase(ea=six.integer_types)
    @classmethod
    def add(cls, func, ea):
        '''Add the chunk starting at address `ea` to the function `func`.'''
        fn = by(func)
        start = interface.address.inside(ea)
        if not idaapi.append_func_tail(fn, start, idaapi.BADADDR):
            fullname = '.'.join([getattr(idaapi.append_func_tail, attribute) for attribute in ['__module__', '__name__'] if hasattr(idaapi.append_func_tail, attribute)])
            raise E.DisassemblerError(u"{:s}.add({!r}, {:#x}) : Unable add the chunk at the specified address ({:#x}) to the function at {:#x} with `{:s}`.".format('.'.join([__name__, cls.__name__]), func, ea, start, interface.range.start(fn), fullname))
        ui.state.wait()
        return cls(start)
    @utils.multicase(start=six.integer_types, end=six.integer_types)
    @classmethod
    def add(cls, func, start, end):
        '''Add the chunk from the address `start` until `end` to the function `func`.'''
        fn = by(func)
        ea, stop = bounds = interface.bounds_t(*interface.address.within(start, end))
        if not idaapi.append_func_tail(fn, ea, stop):
            fullname = '.'.join([getattr(idaapi.append_func_tail, attribute) for attribute in ['__module__', '__name__'] if hasattr(idaapi.append_func_tail, attribute)])
            raise E.DisassemblerError(u"{:s}.add({!r}, {:#x}, {:#x}) : Unable add the specified chunk ({:s}) to the function at {:#x} with `{:s}`.".format('.'.join([__name__, cls.__name__]), func, start, end, bounds, interface.range.start(fn), fullname))
        ui.state.wait()
        return cls(ea)
    @utils.multicase(bounds=tuple)
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
    @utils.multicase(ea=six.integer_types)
    @classmethod
    def remove(cls, ea):
        '''Remove the chunk at `ea` from its function.'''
        return cls.remove(ea, ea)
    @utils.multicase(bounds=tuple)
    @classmethod
    def remove(cls, bounds):
        '''Remove the chunk specified by `bounds` from its function.'''
        ea, _ = bounds
        return cls.remove(ea, ea)
    @utils.multicase(ea=six.integer_types)
    @classmethod
    def remove(cls, func, ea):
        '''Remove the chunk at `ea` from the function `func`.'''
        fn, ea = by(func), interface.address.within(ea)
        bounds = cls(ea)
        if not idaapi.remove_func_tail(fn, ea):
            fullname = '.'.join([getattr(idaapi.remove_func_tail, attribute) for attribute in ['__module__', '__name__'] if hasattr(idaapi.remove_func_tail, attribute)])
            raise E.DisassemblerError(u"{:s}.remove({!r}, {:#x}) : Unable to delete the chunk ({:s}) for the function at {:#x} with `{:s}`.".format('.'.join([__name__, cls.__name__]), func, ea, bounds, interface.range.start(fn), fullname))
        return bounds
    @utils.multicase(bounds=tuple)
    @classmethod
    def remove(cls, func, bounds):
        '''Remove the chunk specified by `bounds` from the function `func`.'''
        ea, _ = bounds
        return cls.remove(func, ea)
add_chunk, remove_chunk = utils.alias(chunk.add, 'chunk'), utils.alias(chunk.remove, 'chunk')

@utils.multicase()
def within():
    '''Return if the current address is within a function.'''
    return within(ui.current.address())
@utils.multicase(ea=six.integer_types)
def within(ea):
    '''Return if the address `ea` is within a function.'''
    try:
        ea = interface.address.within(ea)
    except E.OutOfBoundsError:
        return False
    return idaapi.get_func(ea) is not None and idaapi.segtype(ea) != idaapi.SEG_XTRN

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
    @utils.multicase()
    def __new__(cls, func, **external):
        '''Returns the bounds of each basic block for the function `func`.'''
        iterable = cls.iterate(func, **external)
        return [ interface.range.bounds(bb) for bb in iterable ]
    @utils.multicase(bounds=tuple)
    def __new__(cls, bounds, **external):
        '''Return each basic block contained within the specified `bounds`.'''
        (left, _), (_, right) = map(interface.range.unpack, map(cls.at, bounds))
        return cls(left, right + 1, **external)
    @utils.multicase()
    def __new__(cls, left, right, **external):
        """Returns each basic block contained between the addresses `left` and `right`.

        If `external` is true, then include all blocks that are a branch target despite being outside the function boundaries.
        If `split` is false, then do not allow a call instruction to split a block.
        """
        fn = by_address(left)

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
    @utils.multicase()
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
    @utils.multicase(flags=six.integer_types)
    @classmethod
    def iterate(cls, func, flags, **silent):
        '''Returns each ``idaapi.BasicBlock`` from the flowchart built with the specified `flags` (``idaapi.FC_*``) for the function `func`.'''
        fn, FC_CALL_ENDS, has_calls = by(func), getattr(idaapi, 'FC_CALL_ENDS', 0x20), hasattr(idaapi, 'FC_CALL_ENDS')
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
                start, stop, locations = left, right, [ea for ea in block.iterate(bb) if instruction.type.is_call(ea)]
                for item in locations:
                    left, right = start, database.address.next(item)
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
    @utils.multicase()
    @classmethod
    def walk(cls, func, **flags):
        '''Traverse each of the successor blocks starting from the beginning of the function `func`.'''
        fn = by(func)
        return cls.traverse(fn, interface.range.start(fn), operator.methodcaller('succs'), **flags)
    @utils.multicase(ea=six.integer_types)
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
    @utils.multicase(ea=six.integer_types)
    @classmethod
    def moonwalk(cls, ea, **flags):
        '''Traverse each of the predecessor blocks for a function starting with the block at the address `ea`.'''
        return cls.traverse(ea, ea, operator.methodcaller('preds'), **flags)
    @utils.multicase(ea=six.integer_types)
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
    @utils.multicase(predicate=callable)
    @classmethod
    def traverse(cls, predicate, **flags):
        '''Traverse the blocks from the beginning of the current function until the callable `predicate` returns no more elements.'''
        fn = ui.current.function()
        return cls.traverse(fn, interface.range.start(fn), predicate, **flags)
    @utils.multicase(predicate=callable)
    @classmethod
    def traverse(cls, func, predicate, **flags):
        '''Traverse the blocks from the beginning of function `func` until the callable `predicate` returns no more elements.'''
        fn = by(func)
        ea = interface.range.start(fn)
        return cls.traverse(fn, ea, predicate, **flags)
    @utils.multicase(ea=six.integer_types, predicate=callable)
    @classmethod
    def traverse(cls, func, ea, predicate, **flags):
        '''Traverse the blocks of function `func` from the block given by `ea` until the callable `predicate` returns no more elements.'''
        fn = by(func)
        bb = cls.at(fn, ea, **flags)
        return cls.traverse(bb, predicate)
    @utils.multicase(bb=idaapi.BasicBlock, predicate=callable)
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
            elif isinstance(item, six.integer_types):
                iterable = (choice for choice in choices if choice.contains(item))
            elif item in items:
                iterable = (choice for choice in [item])
            else:
                iterable = (choice for choice in [])

            # grab our result and error out if its an integer and didn't match a block.
            result = builtins.next(iterable, None)
            if result is None and isinstance(item, six.integer_types):
                message = 'any of the available blocks' if len(items) > 1 else 'the only available block'
                raise E.ItemNotFoundError(u"{:s}.traverse({!s}) : The specified address ({:#x}) is not within {:s} ({:s}).".format('.'.join([__name__, cls.__name__]), bb, item, message, ', '.join(map("{:s}".format, items))))

            # otherwise, it was something else, and we couldn't match it.
            elif result is None:
                item_descr = interface.bounds_t(*item) if isinstance(item, tuple) else "{!s}".format(item)
                message = 'is not one of the available choices' if len(items) > 1 else 'does not match the only available block'
                raise E.ItemNotFoundError(u"{:s}.traverse({!s}) : The specified block ({:s}) {:s} ({:s}).".format('.'.join([__name__, cls.__name__]), bb, item_descr, message, ', '.join(map("{:s}".format, items))))
            return result

        # start out with the basic-block we were given, and use it for each decision.
        available = {interface.range.bounds(bb) : bb}
        choices = [item for item in available]

        # continue while we still have choices to choose from.
        while len(choices):
            selected = (yield choices if len(choices) > 1 else choices[0])
            choice = Fchoose(selected, choices)
            items, _ = predicate(available[choice]), visited.add(choice)
            available = {interface.range.bounds(item) : item for item in items}
            choices = [item for item in available]
        return

    @utils.multicase()
    @classmethod
    def at(cls, **flags):
        '''Return the ``idaapi.BasicBlock`` at the current address in the current function.'''
        return cls.at(ui.current.function(), ui.current.address(), **flags)
    @utils.multicase(ea=six.integer_types)
    @classmethod
    def at(cls, ea, **flags):
        '''Return the ``idaapi.BasicBlock`` of address `ea` in the current function.'''
        fn = by_address(ea)
        return cls.at(fn, ea, **flags)
    @utils.multicase(ea=six.integer_types)
    @classmethod
    def at(cls, func, ea, **flags):
        '''Return the ``idaapi.BasicBlock`` in function `func` at address `ea`.'''
        FC_NOEXT, FC_CALL_ENDS = getattr(idaapi, 'FC_NOEXT', 2), getattr(idaapi, 'FC_CALL_ENDS', 0x20)
        fc_flags = flags.get('flags', idaapi.FC_PREDS | FC_NOEXT)
        fc_flags |= 0 if any(not flags[item] for item in ['call', 'calls', 'split'] if item in flags) else FC_CALL_ENDS
        return cls.at(func, ea, fc_flags)
    @utils.multicase(ea=six.integer_types, flags=six.integer_types)
    @classmethod
    def at(cls, func, ea, flags):
        '''Return the ``idaapi.BasicBlock`` with the specified `flags` (``idaapi.FC_*``) for function `func` at address `ea`.'''
        fn = by(func)
        for bb in cls.iterate(fn, flags):
            if interface.range.within(ea, bb):
                return bb
            continue
        raise E.AddressNotFoundError(u"{:s}.at({:#x}, {:#x}) : Unable to locate `idaapi.BasicBlock` for address {:#x} in the specified function ({:#x}).".format('.'.join([__name__, cls.__name__]), interface.range.start(fn), ea, ea, interface.range.start(fn)))
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
            fn = func.by(bounds.left)
            logging.warning(u"{:s}.at({!s}) : Unable to determine the flowchart from the provided `idaapi.BasicBlock` ({:s}) for function {:#x}.".format('.'.join([__name__, cls.__name__]), bounds, bounds, interface.range.start(fn)))
            return cls.at(fn, bb)

        # now we can extract the function and its flags to regenerate the flowchart.
        fn, flags = fc.pfn, fc.flags

        # regenerate the flowchart, and generate an iterator that gives us matching
        # blocks so that we can return the first one that matches.
        iterable = (item for item in cls.iterate(fn, flags) if bounds.left == interface.range.start(item) or bounds.contains(interface.range.start(item)))
        result = builtins.next(iterable, None)
        if result is None:
            raise E.ItemNotFoundError(u"{:s}.at({!s}) : Unable to locate the `idaapi.BasicBlock` for the given bounds ({:s}) in function {:#x}.".format('.'.join([__name__, cls.__name__]), interface.range.start(fn), bounds, bounds, interface.range.start(fn)))
        return result
    @utils.multicase(bb=idaapi.BasicBlock)
    @classmethod
    def at(cls, func, bb):
        '''Return the ``idaapi.BasicBlock`` in function `func` identifed by `bb`.'''
        fn, bounds = by(func), interface.range.bounds(bb)

        # now we need to extract the flags from the fc if possible.
        path = map(operator.attrgetter, ['_fc', '_q', 'flags'])
        try:
            flags = functools.reduce(lambda agg, item: item(agg), path, bb)

        # warn the user about not being able to figure it out.
        except AttributeError:
            flags = idaapi.FC_PREDS | idaapi.FC_NOEXT
            logging.warning(u"{:s}.at({:#x}, {!s}) : Unable to determine the original flags for the `idaapi.BasicBlock` ({:s}) in function {:#x}.".format('.'.join([__name__, cls.__name__]), interface.range.start(fn), interface.range.bounds(bb), interface.range.start(fn)))

        # regenerate the flowchart, and generate an iterator that gives
        # us matching blocks. then we can return the first one and be good.
        iterable = (item for item in cls.iterate(fn, flags) if bounds.left == interface.range.start(item) or bounds.contains(interface.range.start(item)))
        result = builtins.next(iterable, None)
        if result is None:
            raise E.ItemNotFoundError(u"{:s}.at({:#x}, {!s}) : Unable to locate the `idaapi.BasicBlock` for the given bounds ({:s}) in function {:#x}.".format('.'.join([__name__, cls.__name__]), interface.range.start(fn), bounds, bounds, interface.range.start(fn)))
        return result

    @utils.multicase()
    @classmethod
    def flowchart(cls, **flags):
        '''Return an ``idaapi.FlowChart`` object for the current function.'''
        return cls.flowchart(ui.current.function(), **flags)
    @utils.multicase()
    @classmethod
    def flowchart(cls, func, **flags):
        '''Return an ``idaapi.FlowChart`` object for the function `func`.'''
        return cls.flowchart(func, flags.get('flags', idaapi.FC_PREDS))
    @utils.multicase(flags=six.integer_types)
    @classmethod
    def flowchart(cls, func, flags):
        '''Return an ``idaapi.FlowChart`` object built with the specified `flags` for the function `func`.'''
        fn = by(func)
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
            raise E.InvalidTypeOrValueError(u"{:s}.at({!s}) : Unable to determine the flowchart from the provided `idaapi.BasicBlock` ({:s}).".format('.'.join([__name__, cls.__name__]), bounds, bounds))
        return fc

    @utils.multicase()
    @classmethod
    @utils.string.decorate_arguments('And', 'Or')
    def select(cls, **boolean):
        '''Query the basic blocks of the current function for any tags specified by `boolean`'''
        return cls.select(ui.current.function(), **boolean)
    @utils.multicase(tag=six.string_types)
    @classmethod
    @utils.string.decorate_arguments('tag', 'And', 'Or')
    def select(cls, tag, *Or, **boolean):
        '''Query the basic blocks of the current function for the specified `tag` and any others specified as `Or`.'''
        res = {tag} | {item for item in Or}
        boolean['Or'] = {item for item in boolean.get('Or', [])} | res
        return cls.select(ui.current.function(), **boolean)
    @utils.multicase(tag=six.string_types)
    @classmethod
    @utils.string.decorate_arguments('tag', 'And', 'Or')
    def select(cls, func, tag, *Or, **boolean):
        '''Query the basic blocks of the function `func` for the specified `tag` and any others specified as `Or`.'''
        res = {tag} | {item for item in Or}
        boolean['Or'] = {item for item in boolean.get('Or', [])} | res
        return cls.select(func, **boolean)
    @utils.multicase(tag=(builtins.set, builtins.list))
    @classmethod
    @utils.string.decorate_arguments('tag', 'And', 'Or')
    def select(cls, func, tag, *Or, **boolean):
        '''Query the basic blocks of the function `func` for the specified `tag` and any others specified as `Or`.'''
        res = {item for item in tag} | {item for item in Or}
        boolean['Or'] = {item for item in boolean.get('Or', [])} | res
        return cls.select(func, **boolean)
    @utils.multicase()
    @classmethod
    @utils.string.decorate_arguments('And', 'Or')
    def select(cls, func, **boolean):
        """Query the basic blocks of the function `func` for any tags specified by `boolean`. Yields each basic block found along with the matching tags as a dictionary.

        If `And` contains an iterable then require the returned address contains them.
        If `Or` contains an iterable then include any other tags that are specified.
        """
        target, flags = by(func), getattr(idaapi, 'FC_NOEXT', 2) | getattr(idaapi, 'FC_CALL_ENDS', 0x20)

        # Turn all of our parameters into a dict of sets that we can iterate through.
        containers = (builtins.tuple, builtins.set, builtins.list)
        boolean = {key : {item for item in value} if isinstance(value, containers) else {value} for key, value in boolean.items()}

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
                address = database.tag(ea)
                if address: yield interface.range.bounds(results[ea]), address
            return

        # Collect the tagnames being queried as specified by the user.
        Or, And = ({item for item in boolean.get(B, [])} for B in ['Or', 'And'])

        # Walk through every tagged address and cross-check it against the query.
        for ea in ordered:
            ui.navigation.analyze(ea)
            collected, address = {}, database.tag(ea)

            # Or(|) includes any of the tagnames that were selected.
            collected.update({key : value for key, value in address.items() if key in Or})

            # And(&) includes tags only if the address includes all of the specified tagnames.
            if And:
                if And & six.viewkeys(address) == And:
                    collected.update({key : value for key, value in address.items() if key in And})
                else: continue

            # If anything was collected (matched), then yield the block and the matching tags.
            if collected: yield interface.range.bounds(results[ea]), collected
        return

    @utils.multicase()
    @classmethod
    def digraph(cls):
        '''Return a ``networkx.DiGraph`` of the function at the current address.'''
        return cls.digraph(ui.current.function())
    @utils.multicase()
    @classmethod
    def digraph(cls, func, **flags):
        """Return a ``networkx.DiGraph`` of the function `func`.

        Requires the ``networkx`` module in order to build the graph.
        """
        fn, fcflags = by(func), flags.get('flags', idaapi.FC_PREDS | idaapi.FC_NOEXT | getattr(idaapi, 'FC_CALL_ENDS', 0x20))
        ea = interface.range.start(fn)

        # assign some default values and create some tools to use when creating the graph
        availableChunks = [item for item in chunks(ea)]

        # create digraph
        import networkx
        attrs = tag(ea)
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

        if color(fn) is not None:
            operator.setitem(attrs, '__color__', color(fn))

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
                items = [item for item in database.address.iterate(bounds)]
                last = database.address.prev(bounds.right)

            # as the boundaries are defining an empty basic-block, we only need
            # to find the one address that it's actually pointing to.
            else:
                items = [item for item in {bound for bound in bounds}]
                last, = items

            # figure out all of the tags in the list of addresses (items).
            tags = [database.tag(item) for item in items]

            # now we can continue to collect attributes to add to our graph.
            attrs = database.tag(bounds.left)
            comment = attrs.pop('', None)
            comment and attrs.setdefault('__comment__', comment)

            attrs.setdefault('__count__', len(items))
            attrs.setdefault('__bounds__', bounds)
            attrs.setdefault('__address__', bounds.left)
            attrs.setdefault('__edge__', last)
            attrs.setdefault('__size__', getattr(bounds, 'size', bounds.right - bounds.left))

            attrs.setdefault('__entry__', bounds.left == ea or not any(B.preds()))
            attrs.setdefault('__sentinel__', instruction.type.is_sentinel(last) or not any(B.succs()))
            attrs.setdefault('__conditional__', instruction.type.is_jxx(last))
            attrs.setdefault('__unconditional__', any(F(last) for F in [instruction.type.is_jmp, instruction.type.is_jmpi]))
            attrs.setdefault('__calls__', [ea for ea in items if instruction.type.is_call(ea)])

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
                attrs.setdefault('__name__', database.name(bounds.left) or name(bounds.left))

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
                source, target = database.address.prev(interface.range.end(Bp)), interface.range.start(B)

                # FIXME: figure out some more default attributes to include
                attrs = {}
                if interface.range.end(Bp) == target:
                    operator.setitem(attrs, '__contiguous__', interface.range.end(Bp) == target)
                elif instruction.type.is_jxx(source):
                    operator.setitem(attrs, '__conditional__', True)
                elif instruction.type.is_jmp(source) or instruction.type.is_jmpi(source):
                    operator.setitem(attrs, '__unconditional__', True)
                else:
                    operator.setitem(attrs, '__branch__', instruction.type.is_branch(source))

                # add the dot attributes for the edge
                operator.setitem(attrs, 'dir', 'forward')

                if any(attrs.get(item, False) for item in ['__branch__', '__conditional__', '__unconditional__']):
                    attrs['label'] = instruction.mnem(source)

                # add the edge to the predecessor
                G.add_edge(interface.range.start(Bp), target, **attrs)

            # ...add an edge for its successors
            for Bs in B.succs():
                source, target = database.address.prev(interface.range.end(B)), interface.range.start(Bs)

                # FIXME: figure out some more default attributes to include
                attrs = {}
                if interface.range.end(B) == target:
                    operator.setitem(attrs, '__contiguous__', interface.range.end(B) == target)
                elif instruction.type.is_jxx(source):
                    operator.setitem(attrs, '__conditional__', True)
                elif instruction.type.is_jmp(source) or instruction.type.is_jmpi(source):
                    operator.setitem(attrs, '__unconditional__', True)
                else:
                    operator.setitem(attrs, '__branch__', instruction.type.is_branch(source))

                # add the dot attributes for the edge
                operator.setitem(attrs, 'dir', 'forward')

                if any(attrs.get(item, False) for item in ['__branch__', '__conditional__', '__unconditional__']):
                    attrs['label'] = instruction.mnem(source)

                # add the edge to the successor
                G.add_edge(interface.range.start(B), target, **attrs)
            continue
        return G
    graph = utils.alias(digraph, 'blocks')

    @utils.multicase(start=six.integer_types, exits=(six.integer_types, builtins.list, builtins.tuple, builtins.set))
    @classmethod
    def subgraph(cls, start, exits):
        '''Return a ``networkx.DiGraph`` subgraph of the current function from address `start` and terminating at any address in `exits`.'''
        return cls.subgraph(ui.current.function(), start, exits)
    @utils.multicase(start=six.integer_types, exits=(six.integer_types, builtins.list, builtins.tuple, builtins.set))
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
    @utils.multicase(ea=six.integer_types)
    @classmethod
    def at(cls, ea, **flags):
        '''Return the ``idaapi.BasicBlock`` of address `ea` in the current function.'''
        fn = by_address(ea)
        return cls.at(fn, ea, **flags)
    @utils.multicase(ea=six.integer_types)
    @classmethod
    def at(cls, func, ea, **flags):
        '''Return the ``idaapi.BasicBlock`` of address `ea` in the function `func`.'''
        return blocks.at(func, ea, **flags)
    @utils.multicase(bb=idaapi.BasicBlock)
    @classmethod
    def at(cls, bb):
        '''Return the ``idaapi.BasicBlock`` of the basic block `bb`.'''
        return bb
    @utils.multicase(bounds=builtins.tuple)
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
    @utils.multicase(ea=six.integer_types)
    @classmethod
    def id(cls, ea):
        '''Return the block id of address `ea` in the current function.'''
        return cls.at(ea).id
    @utils.multicase(ea=six.integer_types)
    @classmethod
    def id(cls, func, ea):
        '''Return the block id of address `ea` in the function `func`.'''
        return cls.at(func, ea).id
    @utils.multicase(bb=idaapi.BasicBlock)
    @classmethod
    def id(cls, bb):
        '''Return the block id of the basic block `bb`.'''
        return bb.id
    @utils.multicase(bounds=builtins.tuple)
    @classmethod
    def id(cls, bounds):
        '''Return the block id of the basic block identified by `bounds`.'''
        return cls.at(bounds).id

    @utils.multicase()
    def __new__(cls, **flags):
        '''Returns the boundaries of the current basic block.'''
        return cls(ui.current.function(), ui.current.address(), **flags)
    @utils.multicase(ea=six.integer_types)
    def __new__(cls, ea, **flags):
        '''Returns the boundaries of the basic block at address `ea`.'''
        return cls(by_address(ea), ea, **flags)
    @utils.multicase(ea=six.integer_types)
    def __new__(cls, func, ea, **flags):
        '''Returns the boundaries of the basic block at address `ea` in function `func`.'''
        res = blocks.at(func, ea, **flags)
        return interface.range.bounds(res)
    @utils.multicase(ea=six.integer_types, flags=six.integer_types)
    def __new__(cls, func, ea, flags):
        '''Returns the boundaries of the basic block with the specified `flags` (``idaapi.FC_*``) at address `ea` in function `func`.'''
        res = blocks.at(func, ea, flags)
        return interface.range.bounds(res)
    @utils.multicase(bb=idaapi.BasicBlock)
    def __new__(cls, bb):
        '''Returns the boundaries of the basic block `bb`.'''
        return interface.range.bounds(bb)
    @utils.multicase(bounds=builtins.tuple)
    def __new__(cls, bounds, **flags):
        '''Return the boundaries of the basic block identified by `bounds`.'''
        left, _ = bounds
        return cls(left, **flags)

    @utils.multicase(ea=six.integer_types)
    @classmethod
    def contains(cls, ea):
        '''Return whether the address `ea` is within the current basic block.'''
        left, right = cls()
        return left <= ea < right
    @utils.multicase(address=six.integer_types, ea=six.integer_types)
    @classmethod
    def contains(cls, address, ea):
        '''Return whether the address `ea` is within the basic block at the specified `address`.'''
        left, right = cls(address)
        return left <= ea < right
    @utils.multicase(address=six.integer_types, ea=six.integer_types)
    @classmethod
    def contains(cls, func, address, ea):
        '''Return whether the address `ea` is within the basic block for the function `func` at the specified `address`.'''
        left, right = cls(func, address)
        return left <= ea < right
    @utils.multicase(bb=idaapi.BasicBlock, ea=six.integer_types)
    @classmethod
    def contains(cls, bb, ea):
        '''Return whether the address `ea` is within the basic block `bb`.'''
        left, right = cls(bb)
        return left <= ea < right
    @utils.multicase(bounds=builtins.tuple, ea=six.integer_types)
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
    @utils.multicase(ea=six.integer_types)
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
    @utils.multicase(bounds=builtins.tuple)
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
    @utils.multicase(ea=six.integer_types)
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
    @utils.multicase(bounds=builtins.tuple)
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
    @utils.multicase(ea=six.integer_types)
    @classmethod
    def address(cls, ea):
        '''Return the top address for the basic block containing the address `ea`.'''
        return cls.address(ea, 0)
    @utils.multicase(ea=six.integer_types, offset=six.integer_types)
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
    @utils.multicase(ea=six.integer_types)
    @classmethod
    def offset(cls, ea):
        '''Return the offset from the base of the database for the basic block at the address `ea`.'''
        return cls.offset(ea, 0)
    @utils.multicase(ea=six.integer_types, offset=six.integer_types)
    @classmethod
    def offset(cls, ea, offset):
        '''Return the offset from the base of the database for the basic block at address `ea` and add the provided `offset` to it.'''
        left, _ = cls(ea)
        return database.address.offset(left) + offset

    @utils.multicase()
    @classmethod
    def color(cls):
        '''Returns the color of the basic block at the current address.'''
        return cls.color(ui.current.address())
    @utils.multicase(none=None.__class__)
    @classmethod
    def color(cls, none):
        '''Removes the color of the basic block at the current address.'''
        return cls.color(ui.current.address(), None)
    @utils.multicase(ea=six.integer_types)
    @classmethod
    def color(cls, ea):
        '''Returns the color of the basic block at the address `ea`.'''
        bb = cls.at(ea)
        return cls.color(bb)
    @utils.multicase(bb=idaapi.BasicBlock)
    @classmethod
    def color(cls, bb):
        '''Returns the color of the basic block `bb`.'''
        get_node_info = idaapi.get_node_info2 if idaapi.__version__ < 7.0 else idaapi.get_node_info

        fn, ni = by_address(interface.range.start(bb)), idaapi.node_info_t()
        ok = get_node_info(ni, interface.range.start(fn), bb.id)
        if ok and ni.valid_bg_color():
            res = ni.bg_color
            b, r = (res&0xff0000)>>16, res&0x0000ff
            return (r<<16) | (res&0x00ff00) | b
        return None
    @utils.multicase(bounds=builtins.tuple)
    @classmethod
    def color(cls, bounds):
        '''Returns the color of the basic block identified by `bounds`.'''
        bb = cls.at(bounds)
        return cls.color(bb)
    @utils.multicase(ea=six.integer_types, none=None.__class__)
    @classmethod
    def color(cls, ea, none):
        '''Removes the color of the basic block at the address `ea`.'''
        clr_node_info = idaapi.clr_node_info2 if idaapi.__version__ < 7.0 else idaapi.clr_node_info

        res, fn, bb = cls.color(ea), by_address(ea), cls.id(ea)
        try: clr_node_info(interface.range.start(fn), bb, idaapi.NIF_BG_COLOR | idaapi.NIF_FRAME_COLOR)
        finally: idaapi.refresh_idaview_anyway()

        # clear the color of each item too.
        for ea in block.iterate(ea):
            database.color(ea, None)
        return res
    @utils.multicase(bounds=builtins.tuple, none=None.__class__)
    @classmethod
    def color(cls, bounds, none):
        '''Removes the color of the basic block identified by `bounds`.'''
        bb = cls.at(bounds)
        return cls.color(bb, None)
    @utils.multicase(bb=idaapi.BasicBlock, none=None.__class__)
    @classmethod
    def color(cls, bb, none):
        '''Removes the color of the basic block `bb`.'''
        clr_node_info = idaapi.clr_node_info2 if idaapi.__version__ < 7.0 else idaapi.clr_node_info

        res, fn = cls.color(bb), by_address(interface.range.start(bb))
        try: clr_node_info(interface.range.start(fn), bb.id, idaapi.NIF_BG_COLOR | idaapi.NIF_FRAME_COLOR)
        finally: idaapi.refresh_idaview_anyway()

        # clear the color of each item too.
        for ea in block.iterate(bb):
            database.color(ea, None)
        return res
    @utils.multicase(ea=six.integer_types, rgb=six.integer_types)
    @classmethod
    def color(cls, ea, rgb, **frame):
        """Sets the color of the basic block at the address `ea` to `rgb`.

        If the color `frame` is specified, set the frame to the specified color.
        """
        set_node_info = idaapi.set_node_info2 if idaapi.__version__ < 7.0 else idaapi.set_node_info

        res, fn, bb = cls.color(ea), by_address(ea), cls.id(ea)
        ni = idaapi.node_info_t()

        # specify the bgcolor
        r, b = (rgb&0xff0000) >> 16, rgb&0x0000ff
        ni.bg_color = ni.frame_color = (b<<16) | (rgb&0x00ff00) | r

        # now the frame color
        frgb = frame.get('frame', 0x000000)
        fr, fb = (frgb&0xff0000)>>16, frgb&0x0000ff
        ni.frame_color = (fb<<16) | (frgb&0x00ff00) | fr

        # set the node
        f = (idaapi.NIF_BG_COLOR|idaapi.NIF_FRAME_COLOR) if frame else idaapi.NIF_BG_COLOR
        try: set_node_info(interface.range.start(fn), bb, ni, f)
        finally: idaapi.refresh_idaview_anyway()

        # update the color of each item too
        for ea in block.iterate(ea):
            database.color(ea, rgb)
        return res
    @utils.multicase(bb=idaapi.BasicBlock, rgb=six.integer_types)
    @classmethod
    def color(cls, bb, rgb, **frame):
        '''Sets the color of the basic block `bb` to `rgb`.'''
        set_node_info = idaapi.set_node_info2 if idaapi.__version__ < 7.0 else idaapi.set_node_info
        res, fn, ni = cls.color(bb), by_address(interface.range.start(bb)), idaapi.node_info_t()

        # specify the bg color
        r, b = (rgb&0xff0000) >> 16, rgb&0x0000ff
        ni.bg_color = ni.frame_color = (b<<16) | (rgb&0x00ff00) | r

        # now the frame color
        frgb = frame.get('frame', 0x000000)
        fr, fb = (frgb&0xff0000)>>16, frgb&0x0000ff
        ni.frame_color = (fb<<16) | (frgb&0x00ff00) | fr

        # set the node
        f = (idaapi.NIF_BG_COLOR|idaapi.NIF_FRAME_COLOR) if frame else idaapi.NIF_BG_COLOR
        try: set_node_info(interface.range.start(fn), bb.id, ni, f)
        finally: idaapi.refresh_idaview_anyway()

        # update the colors of each item too.
        for ea in block.iterate(bb):
            database.color(ea, rgb)
        return res
    @utils.multicase(bounds=builtins.tuple, rgb=six.integer_types)
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
    @utils.multicase(ea=six.integer_types)
    @classmethod
    def before(cls, ea):
        '''Return the addresses of all the instructions that branch to the basic block at address `ea`.'''
        res = blocks.at(ea)
        return cls.before(res)
    @utils.multicase(bounds=builtins.tuple)
    @classmethod
    def before(cls, bounds):
        '''Return the addresses of all the instructions that branch to the basic block identified by `bounds`.'''
        bb = cls.at(bounds)
        return cls.before(bb)
    @utils.multicase(bb=idaapi.BasicBlock)
    @classmethod
    def before(cls, bb):
        '''Return the addresses of all the instructions that branch to the basic block `bb`.'''
        return [ database.address.prev(interface.range.end(bb)) for bb in bb.preds() ]
    predecessors = preds = utils.alias(before, 'block')

    @utils.multicase()
    @classmethod
    def after(cls):
        '''Return the addresses of all the instructions that the current basic block leaves to.'''
        return cls.after(ui.current.address())
    @utils.multicase(ea=six.integer_types)
    @classmethod
    def after(cls, ea):
        '''Return the addresses of all the instructions that the basic block at address `ea` leaves to.'''
        bb = cls.at(ea)
        return cls.after(bb)
    @utils.multicase(bounds=builtins.tuple)
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
    @utils.multicase(ea=six.integer_types)
    @classmethod
    def iterate(cls, ea):
        '''Yield all the addresses in the basic block at address `ea`.'''
        left, right = cls(ea)
        return database.address.iterate(left, right)
    @utils.multicase(bounds=builtins.tuple)
    @classmethod
    def iterate(cls, bounds):
        '''Yield all the addresses in the basic block identified by `bounds`.'''
        return database.address.iterate(bounds)
    @utils.multicase(bb=idaapi.BasicBlock)
    @classmethod
    def iterate(cls, bb):
        '''Yield all the addresses in the basic block `bb`.'''
        left, right = interface.range.unpack(bb)
        return database.address.iterate(left, right)

    # current block
    @utils.multicase()
    @classmethod
    def tag(cls):
        '''Returns all the tags defined for the current basic block.'''
        return cls.tag(ui.current.address())
    @utils.multicase(key=six.string_types)
    @classmethod
    @utils.string.decorate_arguments('key')
    def tag(cls, key):
        '''Returns the value of the tag identified by `key` for the current basic block.'''
        return cls.tag(ui.current.address(), key)
    @utils.multicase(key=six.string_types)
    @classmethod
    @utils.string.decorate_arguments('key')
    def tag(cls, key, value):
        '''Sets the value for the tag `key` to `value` for the current basic block.'''
        return cls.tag(ui.current.address(), key, value)
    @utils.multicase(key=six.string_types, none=None.__class__)
    @classmethod
    @utils.string.decorate_arguments('key')
    def tag(cls, key, none):
        '''Removes the tag identified by `key` for the current basic block.'''
        return cls.tag(ui.current.address(), key, none)

    # address or bounds of block
    @utils.multicase(ea=(six.integer_types, tuple))
    @classmethod
    def tag(cls, ea):
        '''Returns all the tags defined for the basic block at `ea`.'''
        bb = cls.at(ea)
        return cls.tag(bb)
    @utils.multicase(ea=(six.integer_types, tuple), key=six.string_types)
    @classmethod
    @utils.string.decorate_arguments('key')
    def tag(cls, ea, key):
        '''Returns the value of the tag identified by `key` for the basic block at `ea`.'''
        bb = cls.at(ea)
        return cls.tag(bb, key)
    @utils.multicase(ea=(six.integer_types, tuple), key=six.string_types)
    @classmethod
    @utils.string.decorate_arguments('key', 'value')
    def tag(cls, ea, key, value):
        '''Sets the value for the tag `key` to `value` for the basic block at `ea`.'''
        bb = cls.at(ea)
        return cls.tag(bb, key, value)
    @utils.multicase(ea=(six.integer_types, tuple), key=six.string_types, none=None.__class__)
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
        ea = interface.range.start(bb)

        # first thing to do is to read the tags for the address. this
        # gives us "__extra_prefix__", "__extra_suffix__", and "__name__".
        res = database.tag(ea)

        # next, we're going to remove the one implicit tag that we
        # need to handle...and that's the "__color__" tag.
        col, _ = cls.color(bb), res.pop('__color__', None)
        if col is not None: res.setdefault('__color__', col)

        # that was pretty much it, so we can just return our results.
        return res
    @utils.multicase(bb=idaapi.BasicBlock, key=six.string_types)
    @classmethod
    @utils.string.decorate_arguments('key', 'value')
    def tag(cls, bb, key):
        '''Returns the value of the tag identified by `key` from the ``idaapi.BasicBlock`` given in `bb`.'''
        res = cls.tag(bb)
        if key in res:
            return res[key]
        bounds = interface.range.bounds(bb)
        raise E.MissingTagError(u"{:s}.tag({!s}, {!r}) : Unable to read the specified tag (\"{:s}\") from the basic block ({:s}).".format(__name__, bounds, key, utils.string.escape(key, '"'), bounds))
    @utils.multicase(bb=idaapi.BasicBlock, key=six.string_types)
    @classmethod
    @utils.string.decorate_arguments('key', 'value')
    def tag(cls, bb, key, value):
        '''Sets the value for the tag `key` to `value` in the ``idaapi.BasicBlock`` given by `bb`.'''
        ea = interface.range.start(bb)

        # the only real implicit tag we need to handle is "__color__", because our
        # database.tag function does "__extra_prefix__", "__extra_suffix__", and "__name__".
        if key == '__color__':
            return cls.color(bb, value)

        # now we can passthrough to database.tag for everything else.
        return database.tag(ea, key, value)
    @utils.multicase(bb=idaapi.BasicBlock, key=six.string_types, none=None.__class__)
    @classmethod
    @utils.string.decorate_arguments('key')
    def tag(cls, bb, key, none):
        '''Removes the tag identified by `key` from the ``idaapi.BasicBlock`` given by `bb`.'''
        ea = interface.range.start(bb)

        # if the '__color__' tag was specified, then explicitly clear it.
        if key == '__color__':
            return cls.color(bb, none)

        # passthrough to database.tag for removing the ones we don't handle.
        return database.tag(ea, key, none)

    @utils.multicase(reg=(six.string_types, interface.register_t))
    @classmethod
    def register(cls, reg, *regs, **modifiers):
        '''Yield each `(address, opnum, state)` within the current block that uses `reg` or any one of the registers in `regs`.'''
        return cls.register(ui.current.address(), reg, *regs, **modifiers)
    @utils.multicase(ea=six.integer_types, reg=(six.string_types, interface.register_t))
    @classmethod
    def register(cls, ea, reg, *regs, **modifiers):
        '''Yield each `(address, opnum, state)` within the block containing `ea` that uses `reg` or any one of the registers in `regs`.'''
        bb = cls.at(ea, **modifiers)
        return cls.register(bb, reg, *regs, **modifiers)
    @utils.multicase(bounds=builtins.tuple, reg=(six.string_types, interface.register_t))
    @classmethod
    def register(cls, bounds, reg, *regs, **modifiers):
        '''Yield each `(address, opnum, state)` within the block identified by `bounds` that uses `reg` or any one of the registers in `regs`.'''
        iterops = interface.regmatch.modifier(**modifiers)
        uses_register = interface.regmatch.use( (reg,) + regs )

        for ea in database.address.iterate(bounds):
            for opnum in iterops(ea):
                if uses_register(ea, opnum):
                    items = ea, opnum, instruction.op_state(ea, opnum)
                    yield interface.opref_t(*items)
                continue
            continue
        return
    @utils.multicase(bb=idaapi.BasicBlock, reg=(six.string_types, interface.register_t))
    @classmethod
    def register(cls, bb, reg, *regs, **modifiers):
        """Yield each `(address, opnum, state)` within the block `bb` that uses `reg` or any one of the registers in `regs`.

        If the keyword `write` is true, then only return the result if it's writing to the register.
        """
        iterops = interface.regmatch.modifier(**modifiers)
        uses_register = interface.regmatch.use( (reg,) + regs )

        for ea in cls.iterate(bb):
            for opnum in iterops(ea):
                if uses_register(ea, opnum):
                    items = ea, opnum, instruction.op_state(ea, opnum)
                    yield interface.opref_t(*items)
                continue
            continue
        return

    @utils.multicase()
    @classmethod
    def read(cls):
        '''Return all the bytes contained in the current basic block.'''
        return cls.read(ui.current.address())
    @utils.multicase(ea=six.integer_types)
    @classmethod
    def read(cls, ea):
        '''Return all the bytes contained in the basic block at address `ea`.'''
        bb = cls.at(ea)
        return cls.read(bb)
    @utils.multicase(bounds=builtins.tuple)
    @classmethod
    def read(cls, bounds):
        '''Return all the bytes contained in the basic block identified by `bounds`.'''
        bb = cls.at(bounds)
        return cls.read(bb)
    @utils.multicase(bb=idaapi.BasicBlock)
    @classmethod
    def read(cls, bb):
        '''Return all the bytes contained in the basic block `bb`.'''
        bounds = interface.range.bounds(bb)
        return database.read(bounds)

    @utils.multicase()
    @classmethod
    def disassemble(cls, **options):
        '''Returns the disassembly of the basic block at the current address.'''
        return cls.disassemble(ui.current.address(), **options)
    @utils.multicase(ea=six.integer_types)
    @classmethod
    def disassemble(cls, ea, **options):
        '''Returns the disassembly of the basic block at the address `ea`.'''
        F = functools.partial(database.disassemble, **options)
        return '\n'.join(map(F, cls.iterate(ea)))
    @utils.multicase(bounds=builtins.tuple)
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

    # FIXME: implement .decompile for an idaapi.BasicBlock type too
    @utils.multicase()
    @classmethod
    def decompile(cls):
        '''(UNSTABLE) Returns the decompiled code of the basic block at the current address.'''
        return cls.decompile(ui.current.address())
    @utils.multicase(ea=six.integer_types)
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
    function.

    Some ways of using this can be::

        > print( function.frame() )
        > print( hex(function.frame.id(ea)) )
        > sp = function.frame.delta(ea)

    """
    @utils.multicase()
    def __new__(cls):
        '''Return the frame of the current function.'''
        return cls(ui.current.function())

    @utils.multicase()
    def __new__(cls, func):
        '''Return the frame of the function `func`.'''
        fn = by(func)
        res = idaapi.get_frame(interface.range.start(fn))
        if res is not None:
            return structure.by_identifier(res.id, offset=-fn.frsize)
        raise E.MissingTypeOrAttribute(u"{:s}({:#x}) : The specified function does not have a frame.".format('.'.join([__name__, cls.__name__]), interface.range.start(fn)))

    @utils.multicase()
    @classmethod
    def new(cls):
        '''Add an empty frame to the current function.'''
        _r = database.config.bits() // 8
        return cls.new(ui.current.function(), 0, _r, 0)
    @utils.multicase(lvars=six.integer_types, args=six.integer_types)
    @classmethod
    def new(cls, lvars, args):
        '''Add a frame to the current function using the sizes specified by `lvars` for local variables, and `args` for arguments.'''
        _r = database.config.bits() // 8
        return cls.new(ui.current.function(), lvars, _r, args)
    @utils.multicase(lvars=six.integer_types, regs=six.integer_types, args=six.integer_types)
    @classmethod
    def new(cls, lvars, regs, args):
        '''Add a frame to the current function using the sizes specified by `lvars` for local variables, `regs` for frame registers, and `args` for arguments.'''
        return cls.new(ui.current.function(), lvars, regs, args)
    @utils.multicase(lvars=six.integer_types, regs=six.integer_types, args=six.integer_types)
    @classmethod
    def new(cls, func, lvars, regs, args):
        """Add a frame to the function `func` using the sizes specified by `lvars` for local variables, `regs` for frame registers, and `args` for arguments.

        When specifying the size of the registers (`regs`) the size of the saved instruction pointer must also be included.
        """
        fn = by(func)
        _r = database.config.bits() // 8
        ok = idaapi.add_frame(fn, lvars, regs - _r, args)
        if not ok:
            raise E.DisassemblerError(u"{:s}.new({:#x}, {:+#x}, {:+#x}, {:+#x}) : Unable to use `idaapi.add_frame({:#x}, {:d}, {:d}, {:d})` to add a frame to the specified function.".format('.'.join([__name__, cls.__name__]), interface.range.start(fn), lvars, regs - _r, args, interface.range.start(fn), lvars, regs - _r, args))
        return cls(fn)

    @utils.multicase()
    @classmethod
    def id(cls):
        '''Returns the structure id for the current function's frame.'''
        return cls.id(ui.current.function())
    @utils.multicase()
    @classmethod
    def id(cls, func):
        '''Returns the structure id for the function `func`.'''
        fn = by(func)
        return fn.frame

    @utils.multicase()
    @classmethod
    def delta(cls):
        '''Returns the stack delta for the current address within its function.'''
        return cls.delta(ui.current.address())
    @utils.multicase(ea=six.integer_types)
    @classmethod
    def delta(cls, ea):
        '''Returns the stack delta for the address `ea` within its given function.'''
        fn, ea = by_address(ea), interface.address.inside(ea)
        return idaapi.get_spd(fn, ea)
    @utils.multicase(ea=six.integer_types)
    @classmethod
    def delta(cls, func, ea):
        '''Returns the stack delta for the address `ea` within the function `func`.'''
        fn, ea = by(func), interface.address.inside(ea)
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
        @utils.multicase()
        def __new__(cls, func):
            '''Yield the `(offset, name, size)` of each argument belonging to the function `func`.'''
            _, ea = interface.addressOfRuntimeOrStatic(func)

            # first we'll need to check if there's a tinfo_t for the address to
            # give it priority over the frame. then we can grab its details.
            if database.type.has_typeinfo(ea):
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
            current, base = 0, sum([fn.frsize, fn.frregs, database.config.bits() // 8])
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
        @utils.multicase(ea=six.integer_types)
        @classmethod
        def location(cls, ea):
            '''Return the list of address locations for each of the parameters that are passed to the function call at `ea`.'''
            if not any(Finstruction(ea) for Finstruction in [instruction.type.is_call, instruction.type.is_branch]):
                raise E.MissingTypeOrAttribute(u"{:s}.location({:#x}) : The instruction at the specified address ({:#x}) is not a function call.".format('.'.join([__name__, cls.__name__]), ea, ea))

            items = idaapi.get_arg_addrs(ea)
            if items is None:
                raise E.DisassemblerError(u"{:s}.location({:#x}) : Unable to retrieve the initialization addresses for the arguments to the function call at {:#x}.".format('.'.join([__name__, cls.__name__]), ea, ea))
            return [ea for ea in items]
        @utils.multicase(ea=six.integer_types, index=six.integer_types)
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
        @utils.multicase()
        @classmethod
        def iterate(cls, func):
            '''Yield the `(member, type, name)` associated with the arguments for the function `func`.'''
            rt, ea = interface.addressOfRuntimeOrStatic(func)
            fn, has_tinfo = None if rt else by(ea), type.has_typeinfo(ea)

            # We need our frame to be correct, so we confirm it by checking the problem queue.
            Fproblem = builtins.next((getattr(idaapi, candidate) for candidate in ['is_problem_present', 'QueueIsPresent'] if hasattr(idaapi, candidate)), utils.fconstant(False))
            PR_BADSTACK = getattr(idaapi, 'PR_BADSTACK', 0xb)

            # Build a lookup table that we'll use to deserialize the correct type for each size.
            bits, tilookup = database.config.bits(), {
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
                    fr, asize, rsize = frame(ea), cls.size(ea), bits // 8 + fn.frregs

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
            tinfo = type(ea)
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
                    translated = operator.add(loc, bits // 8 + (fn.frregs if fn else 0))
                    aname = name or interface.tuplename('arg', translated.offset - bits // 8)
                    try:
                        item = fr.members.by(translated) if fr else translated
                    except (E.MemberNotFoundError, E.OutOfBoundsError):
                        item, name = translated, aname
                    else:
                        name = item.name if fr else aname
                    finally:
                        yield item, ti, name or aname

                # If it's a tuple, then we check if it contains any registers
                # so that way we can process them if necessary. If its a register
                # offset where its second item is an integer and it's zero, then
                # we can simply exclude the offset from our results.
                elif isinstance(loc, builtins.tuple) and any(isinstance(item, interface.register_t) for item in loc):
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
        @utils.multicase()
        @classmethod
        def registers(cls, func):
            '''Return the register information associated with the arguments of the function `func`.'''
            result = []
            for reg, ti, name in cls.iterate(func):
                result.append(reg) if any([isinstance(reg, interface.register_t), isinstance(reg, builtins.tuple) and all(isinstance(item, interface.register_t) for item in reg)]) else None
            return result
        regs = utils.alias(registers, 'frame.args')

        @utils.multicase()
        @classmethod
        def size(cls):
            '''Returns the size of the arguments for the current function.'''
            return cls.size(ui.current.function())
        @utils.multicase()
        @classmethod
        def size(cls, func):
            '''Returns the size of the arguments for the function `func`.'''
            fn = by(func)
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
        @utils.multicase()
        def __new__(cls, func):
            '''Yield the `(offset, name, size)` of each local variable relative to the stack pointer for the function `func`.'''
            fn = by(func)

            # figure out the frame
            fr = idaapi.get_frame(fn)
            if fr is None:  # unable to figure out arguments
                raise E.MissingTypeOrAttribute(u"{:s}({:#x}) : Unable to get the function frame.".format('.'.join([__name__, cls.__name__]), interface.range.start(fn)))

            results = []
            for off, size, content in structure.fragment(fr.id, 0, fn.frsize):
                results.append((off - sum([fn.frsize, fn.frregs]), content.get('__name__', None), size))
            return results

        @utils.multicase()
        @classmethod
        def size(cls):
            '''Returns the size of the local variables for the current function.'''
            return cls.size(ui.current.function())
        @utils.multicase()
        @classmethod
        def size(cls, func):
            '''Returns the size of the local variables for the function `func`.'''
            fn = by(func)
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
        @utils.multicase()
        def __new__(cls, func):
            '''Yield the `(offset, name, size)` of each saved register relative to the stack pointer of the function `func`.'''
            fn = by(func)

            # figure out the frame
            fr = idaapi.get_frame(fn)
            if fr is None:  # unable to figure out arguments
                raise E.MissingTypeOrAttribute(u"{:s}({:#x}) : Unable to get the function frame.".format('.'.join([__name__, cls.__name__]), interface.range.start(fn)))

            results = []
            for off, size, content in structure.fragment(fr.id, fn.frsize, sum([fn.frregs, database.config.bits() // 8])):
                results.append((off - sum([fn.frsize, fn.frregs]), content.get('__name__', None), size))
            return results

        @utils.multicase()
        @classmethod
        def size(cls):
            '''Returns the number of bytes occupied by the saved registers in the current function.'''
            return cls.size(ui.current.function())
        @utils.multicase()
        @classmethod
        def size(cls, func):
            '''Returns the number of bytes occupied by the saved registers for the function `func`.'''
            fn = by(func)
            # include the size of a word for the pc because ida doesn't count it
            return fn.frregs + database.config.bits() // 8

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
    return tag(ui.current.address())
@utils.multicase(key=six.string_types)
@utils.string.decorate_arguments('key')
def tag(key):
    '''Returns the value of the tag identified by `key` for the current function.'''
    return tag(ui.current.address(), key)
@utils.multicase(key=six.string_types)
@utils.string.decorate_arguments('key', 'value')
def tag(key, value):
    '''Sets the value for the tag `key` to `value` for the current function.'''
    return tag(ui.current.address(), key, value)
@utils.multicase(key=six.string_types)
@utils.string.decorate_arguments('key')
def tag(func, key):
    '''Returns the value of the tag identified by `key` for the function `func`.'''
    res = tag(func)
    if key in res:
        return res[key]
    raise E.MissingFunctionTagError(u"{:s}.tag({:s}, {!r}) : Unable to read the specified tag (\"{:s}\") from the function.".format(__name__, ("{:#x}" if isinstance(func, six.integer_types) else "{!r}").format(func), key, utils.string.escape(key, '"')))
@utils.multicase()
def tag(func):
    '''Returns all the tags defined for the function `func`.'''
    MANGLED_CODE, MANGLED_DATA, MANGLED_UNKNOWN = getattr(idaapi, 'MANGLED_CODE', 0), getattr(idaapi, 'MANGLED_DATA', 1), getattr(idaapi, 'MANGLED_UNKNOWN', 2)
    Fmangled_type = idaapi.get_mangled_name_type if hasattr(idaapi, 'get_mangled_name_type') else utils.fcompose(utils.frpartial(idaapi.demangle_name, 0), utils.fcondition(operator.truth)(0, MANGLED_UNKNOWN))
    MNG_NODEFINIT, MNG_NOPTRTYP, MNG_LONG_FORM = getattr(idaapi, 'MNG_NODEFINIT', 8), getattr(idaapi, 'MNG_NOPTRTYP', 7), getattr(idaapi, 'MNG_LONG_FORM', 0x6400007)

    try:
        rt, ea = interface.addressOfRuntimeOrStatic(func)

    # If the given location was not within a function, then fall back to a database tag.
    except E.FunctionNotFoundError:
        logging.warning(u"{:s}.tag({:s}) : Attempted to read any tags from a non-function. Falling back to using database tags.".format(__name__, ("{:#x}" if isinstance(func, six.integer_types) else "{!r}").format(func)))
        return database.tag(func)

    # If we were given a runtime function, then the address actually uses a database tag.
    if rt:
        logging.warning(u"{:s}.tag({:#x}) : Attempted to read any tags from a runtime-linked address. Falling back to using database tags.".format(__name__, ea))
        return database.tag(ea)

    # Read both repeatable and non-repeatable comments from the address, and
    # decode the tags that are stored within to a dictionary.
    fn, repeatable = by_address(ea), True
    res = comment(fn, repeatable=False)
    d1 = internal.comment.decode(res)
    res = comment(fn, repeatable=True)
    d2 = internal.comment.decode(res)

    # Detect if the address had content in both repeatable or non-repeatable
    # comments so we can warn the user about what we're going to do.
    if six.viewkeys(d1) & six.viewkeys(d2):
        logging.info(u"{:s}.tag({:#x}) : Contents of both the repeatable and non-repeatable comment conflict with one another due to using the same keys ({!r}). Giving the {:s} comment priority.".format(__name__, ea, ', '.join(six.viewkeys(d1) & six.viewkeys(d2)), 'repeatable' if repeatable else 'non-repeatable'))

    # Then we can store them into a dictionary whilst preserving priority.
    res = {}
    [ res.update(d) for d in ([d1, d2] if repeatable else [d2, d1]) ]

    # Collect all of the naming information for the function.
    fname, mangled = name(ea), utils.string.of(idaapi.get_func_name(ea))
    if fname and Fmangled_type(utils.string.to(mangled)) != MANGLED_UNKNOWN:
        realname = utils.string.of(idaapi.demangle_name(utils.string.to(mangled), MNG_NODEFINIT|MNG_NOPTRTYP) or fname)
    else:
        realname = fname or ''

    # Add any of the implicit tags for the given function into our results.
    fname = fname
    if fname and database.type.flags(interface.range.start(fn), idaapi.FF_NAME): res.setdefault('__name__', realname)
    fcolor = color(fn)
    if fcolor is not None: res.setdefault('__color__', fcolor)

    # For the function's type information within the implicit "__typeinfo__"
    # tag, we'll need to extract the prototype and the function's name. This
    # is so that we can use the name to emit a proper function prototype.
    try:
        if type.has_prototype(fn):
            ti = type(fn)

            # Filter the name we're going to render with so that it can be parsed properly.
            valid = {item for item in string.digits} | {':'}
            filtered = str().join(item if item in valid or idaapi.is_valid_typename(utils.string.to(item)) else '_' for item in realname)
            validname = ''.join(filtered)

            # Use the validname to render the type into a string so that we
            # can return it to the user in its proper format.
            fprototype = idaapi.print_tinfo('', 0, 0, 0, ti, utils.string.to(validname), '')
            res.setdefault('__typeinfo__', fprototype)

    # If an exception was raised, then we're using an older version of IDA and we
    # need to rip the type information from the unmangled name.
    except E.InvalidTypeOrValueError:
        if fname != realname:
            res.setdefault('__typeinfo__', fname)

    # Finally we can hand our result back to the caller.
    return res
@utils.multicase(key=six.string_types)
@utils.string.decorate_arguments('key', 'value')
def tag(func, key, value):
    '''Sets the value for the tag `key` to `value` for the function `func`.'''
    if value is None:
        raise E.InvalidParameterError(u"{:s}.tag({:s}, {!r}, {!r}) : Tried to set the tag (\"{:s}\") to an unsupported type ({!s}).".format(__name__, ("{:#x}" if isinstance(func, six.integer_types) else "{!r}").format(func), key, value, utils.string.escape(key, '"'), value))

    # Check to see if function tag is being applied to an import
    try:
        rt, ea = interface.addressOfRuntimeOrStatic(func)

    # If we're not even in a function, then use a database tag.
    except E.FunctionNotFoundError:
        logging.warning(u"{:s}.tag({:s}, {!r}, {!r}) : Attempted to set tag (\"{:s}\") for a non-function. Falling back to a database tag.".format(__name__, ("{:#x}" if isinstance(func, six.integer_types) else "{!r}").format(func), key, value, utils.string.escape(key, '"')))
        return database.tag(func, key, value)

    # If we are a runtime-only function, then write the tag to the import
    if rt:
        logging.warning(u"{:s}.tag({:#x}, {!r}, {!r}) : Attempted to set tag (\"{:s}\") for a runtime-linked symbol. Falling back to a database tag.".format(__name__, ea, key, value, utils.string.escape(key, '"')))
        return database.tag(ea, key, value)

    # Otherwise, it's a function.
    fn = by_address(ea)

    # If the user wants to modify any of the implicit tags, then we use the key
    # to figure out which function to dispatch to in order to modify it.
    if key == '__name__':
        return name(fn, value)
    elif key == '__color__':
        return color(fn, value)
    elif key == '__typeinfo__':
        return type(fn, value)

    # Decode both comment types for the function so that we can figure out which
    # type that the tag they specified is currently in. If it's in neither, then
    # we can simply use a repeatable comment because we're a function.
    state_correct = internal.comment.decode(comment(fn, repeatable=True)), True
    state_wrong = internal.comment.decode(comment(fn, repeatable=False)), False
    state, where = state_correct if key in state_correct[0] else state_wrong if key in state_wrong[0] else state_correct

    # Grab the previous value from the correct dictionary, and update it with
    # the new value that was given to us.
    res, state[key] = state.get(key, None), value

    # Now we need to guard the modification of the comment so that we don't
    # mistakenly tamper with any of the reference counts in the tag cache.
    hooks = {'changing_range_cmt', 'range_cmt_changed', 'changing_area_cmt', 'area_cmt_changed'} & {target for target in ui.hook.idb}
    try:
        [ ui.hook.idb.disable(item) for item in hooks ]

    # If we weren't able to disable the hooks due to an exception, then don't
    # bother to re-encoding the tags back into the comment.
    except Exception:
        raise

    # Finally we can encode the modified dict and write it to the function comment.
    else:
        comment(fn, internal.comment.encode(state), repeatable=where)

    # Release the hooks that we disabled since we finished modifying the comment.
    finally:
        [ ui.hook.idb.enable(item) for item in hooks ]

    # If there wasn't a key in any of the dictionaries we decoded, then
    # we know one was added and so we need to update the tagcache.
    if res is None:
        internal.comment.globals.inc(interface.range.start(fn), key)

    # return what we fetched from the dict
    return res
@utils.multicase(key=six.string_types, none=None.__class__)
@utils.string.decorate_arguments('key')
def tag(key, none):
    '''Removes the tag identified by `key` for the current function.'''
    return tag(ui.current.address(), key, None)
@utils.multicase(key=six.string_types, none=None.__class__)
@utils.string.decorate_arguments('key')
def tag(func, key, none):
    '''Removes the tag identified by `key` from the function `func`.'''

    # Check to see if function tag is being applied to an import
    try:
        rt, ea = interface.addressOfRuntimeOrStatic(func)

    # If we're not even in a function, then use a database tag.
    except E.FunctionNotFoundError:
        logging.warning(u"{:s}.tag({:s}, {!r}, {!s}) : Attempted to clear the tag for a non-function. Falling back to a database tag.".format(__name__, ('{:#x}' if isinstance(func, six.integer_types) else '{!r}').format(func), key, none))
        return database.tag(func, key, none)

    # If so, then write the tag to the import
    if rt:
        logging.warning(u"{:s}.tag({:#x}, {!r}, {!s}) : Attempted to set tag for a runtime-linked symbol. Falling back to a database tag.".format(__name__, ea, key, none))
        return database.tag(ea, key, none)

    # Otherwise, it's a function.
    fn = by_address(ea)

    # If the user wants to remove any of the implicit tags, then we need to
    # dispatch to the correct function in order to clear the requested value.
    if key == '__name__':
        return name(fn, None)
    elif key == '__color__':
        return color(fn, None)
    elif key == '__typeinfo__':
        return type(fn, None)

    # Decode both comment types so that we can figure out which comment type
    # the tag they're trying to remove is in. If it's in neither, then we just
    # assume which comment it should be in as an exception will be raised later.
    state_correct = internal.comment.decode(comment(fn, repeatable=True)), True
    state_wrong = internal.comment.decode(comment(fn, repeatable=False)), False
    state, where = state_correct if key in state_correct[0] else state_wrong if key in state_wrong[0] else state_correct

    # If the user's key was not in any of the decoded dictionaries, then raise
    # an exception because the key doesn't exist within the function's tags.
    if key not in state:
        raise E.MissingFunctionTagError(u"{:s}.tag({:#x}, {!r}, {!s}) : Unable to remove non-existent tag (\"{:s}\") from function.".format(__name__, interface.range.start(fn), key, none, utils.string.escape(key, '"')))
    res = state.pop(key)

    # Before modifying the comment, we first need to guard its modification
    # so that the hooks don't also tamper with the reference count in the cache.
    hooks = {'changing_range_cmt', 'range_cmt_changed', 'changing_area_cmt', 'area_cmt_changed'} & {target for target in ui.hook.idb}
    try:
        [ ui.hook.idb.disable(item) for item in hooks ]

    # If an exception was raised while trying to disable the hooks, then we just
    # give up and avoid re-encoding the user's tags back into the comment.
    except Exception:
        raise

    # Finally we can encode the modified dict back into the function comment.
    else:
        comment(fn, internal.comment.encode(state), repeatable=where)

    # Release the hooks that were disabled now that that comment has been written.
    finally:
        [ ui.hook.idb.enable(item) for item in hooks ]

    # If we got here cleanly without an exception, then the tag was successfully
    # removed and we just need to update the tag cache with its removal.
    internal.comment.globals.dec(interface.range.start(fn), key)
    return res

@utils.multicase()
def tags():
    '''Returns all of the content tags for the function at the current address.'''
    return tags(ui.current.address())
@utils.multicase(ea=six.integer_types)
def tags(ea):
    '''Returns all of the content tags for the function at the address `ea`.'''
    fn, owners = by(ea), {item for item in chunk.owners(ea)}

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
@utils.multicase()
def tags(func):
    '''Returns all of the content tags for the function `func`.'''
    fn = by(func)
    ea = interface.range.start(fn)
    return tags(ea)

@utils.multicase()
@utils.string.decorate_arguments('And', 'Or')
def select(**boolean):
    '''Query the contents of the current function for any tags specified by `boolean`'''
    return select(ui.current.function(), **boolean)
@utils.multicase(tag=six.string_types)
@utils.string.decorate_arguments('tag', 'And', 'Or')
def select(tag, *Or, **boolean):
    '''Query the contents of the current function for the specified `tag` and any others specified as `Or`.'''
    res = {tag} | {item for item in Or}
    boolean['Or'] = {item for item in boolean.get('Or', [])} | res
    return select(ui.current.function(), **boolean)
@utils.multicase(tag=six.string_types)
@utils.string.decorate_arguments('tag', 'And', 'Or')
def select(func, tag, *Or, **boolean):
    '''Query the contents of the function `func` for the specified `tag` and any others specified as `Or`.'''
    res = {tag} | {item for item in Or}
    boolean['Or'] = {item for item in boolean.get('Or', [])} | res
    return select(func, **boolean)
@utils.multicase(tag=(builtins.set, builtins.list))
@utils.string.decorate_arguments('tag', 'And', 'Or')
def select(func, tag, *Or, **boolean):
    '''Query the contents of the function `func` for the specified `tag` and any others specified as `Or`.'''
    res = {item for item in tag} | {item for item in Or}
    boolean['Or'] = {item for item in boolean.get('Or', [])} | res
    return select(func, **boolean)
@utils.multicase()
@utils.string.decorate_arguments('And', 'Or')
def select(func, **boolean):
    """Query the contents of the function `func` for any tags specified by `boolean`. Yields each address found along with the matching tags as a dictionary.

    If `And` contains an iterable then require the returned address contains them.
    If `Or` contains an iterable then include any other tags that are specified.
    """
    target = by(func)
    containers = (builtins.tuple, builtins.set, builtins.list)
    boolean = {key : {item for item in value} if isinstance(value, containers) else {value} for key, value in boolean.items()}

    # If nothing specific was queried, then yield all tags that are available.
    if not boolean:
        for ea in sorted(internal.comment.contents.address(interface.range.start(target), target=interface.range.start(target))):
            ui.navigation.analyze(ea)
            address = database.tag(ea)
            if address: yield ea, address
        return

    # Collect the tagnames being queried as specified by the user.
    Or, And = ({item for item in boolean.get(B, [])} for B in ['Or', 'And'])

    # Walk through every tagged address and cross-check it against the query.
    for ea in sorted(internal.comment.contents.address(interface.range.start(target), target=interface.range.start(target))):
        ui.navigation.analyze(ea)
        collected, address = {}, database.tag(ea)

        # Or(|) includes any of the tagnames that were selected.
        collected.update({key : value for key, value in address.items() if key in Or})

        # And(&) includes tags only if the address includes all of the specified tagnames.
        if And:
            if And & six.viewkeys(address) == And:
                collected.update({key : value for key, value in address.items() if key in And})
            else: continue

        # If anything was collected (matched), then yield the address and the matching tags.
        if collected: yield ea, collected
    return

@utils.multicase()
def switches():
    '''Yield each switch found in the current function.'''
    return switches(ui.current.function())
@utils.multicase()
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

        > print( function.type.has_noframe() )
        > for ea in filter(function.type.is_library, database.functions()): ...

    """
    @utils.multicase()
    def __new__(cls):
        '''Return the type information for the current function as an ``idaapi.tinfo_t``.'''
        return cls(ui.current.address())
    @utils.multicase(info=(six.string_types, idaapi.tinfo_t))
    def __new__(cls, info, **guessed):
        '''Apply the type information in `info` to the current function.'''
        return cls(ui.current.address(), info, **guessed)
    @utils.multicase(none=None.__class__)
    def __new__(cls, none):
        '''Remove the type information for the current function.'''
        return cls(ui.current.address(), None)
    @utils.multicase(func=(six.integer_types, idaapi.func_t))
    def __new__(cls, func):
        '''Return the type information for the function `func` as an ``idaapi.tinfo_t``.'''
        _, ea = interface.addressOfRuntimeOrStatic(func)

        # Guess the type information for the function ahead of time because
        # they should _always_ have type information associated with them.
        ti = idaapi.tinfo_t()
        if idaapi.GUESS_FUNC_FAILED == idaapi.guess_tinfo2(ea, ti) if idaapi.__version__ < 7.0 else idaapi.guess_tinfo(ti, ea):
            logging.debug(u"{:s}({:#x}) : Ignoring failure ({:d}) when trying to guess the `{:s}` for the specified function.".format('.'.join([__name__, cls.__name__]), ea, idaapi.GUESS_FUNC_FAILED, ti.__class__.__name__))

        # If we can find a proper typeinfo then use that, otherwise return
        # whatever it was that was guessed.
        return database.type(ea) or ti
    @utils.multicase(info=idaapi.tinfo_t)
    def __new__(cls, func, info, **guessed):
        '''Apply the ``idaapi.tinfo_t`` in `info` to the function `func`.'''
        TINFO_GUESSED, TINFO_DEFINITE = getattr(idaapi, 'TINFO_GUESSED', 0), getattr(idaapi, 'TINFO_DEFINITE', 1)

        # Now we can figure out what address we're actually working with.
        rt, ea = interface.addressOfRuntimeOrStatic(func)

        # If the type is not a function type whatsoever, then bail.
        if not any([info.is_func(), info.is_funcptr()]):
            raise E.InvalidTypeOrValueError("{:s}({:#x}, {!r}) : Refusing to apply a non-function type ({!r}) to the given {:s} ({:#x}).".format('.'.join([__name__, cls.__name__]), ea, "{!s}".format(info), 'address' if rt else 'function', ea))

        # If it's a regular function, then we can just use it as-is.
        if not rt:
            ti = info

        # If we're being used against an export, then we need to make sure that
        # our type is a function pointer and we need to promote it if not.
        elif not info.is_ptr():
            pi = idaapi.ptr_type_data_t()
            pi.obj_type = info
            ti = idaapi.tinfo_t()
            if not ti.create_ptr(pi):
                raise E.DisassemblerError("{:s}({:#x}, {!r}) : Unable to promote type to a pointer due to being applied to a function pointer.".format('.'.join([__name__, cls.__name__]), ea, "{!s}".format(info)))
            logging.warning("{:s}({:#x}, {!r}) : Promoting type ({!r}) to a function pointer ({!r}) due to the address ({:#x}) being runtime-linked.".format('.'.join([__name__, cls.__name__]), ea, "{!s}".format(info), "{!s}".format(info), "{!s}".format(ti), ea))

        # and then we just need to apply the type to the given address.
        result, ok = cls(ea), idaapi.apply_tinfo(ea, ti, TINFO_DEFINITE)
        if not ok:
            raise E.DisassemblerError("{:s}({:#x}, {!r}) : Unable to apply typeinfo ({!r}) to the {:s} ({:#x}).".format('.'.join([__name__, cls.__name__]), ea, "{!s}".format(info), "{!s}".format(ti), 'address' if rt else 'function', ea))

        # since TINFO_GUESSED doesn't always work, we clear aflags here.
        if guessed.get('guessed', False):
            interface.node.aflags(ea, idaapi.AFL_USERTI, 0)
        return result
    @utils.multicase(info=six.string_types)
    @utils.string.decorate_arguments('info')
    def __new__(cls, func, info, **guessed):
        '''Parse the type information string in `info` into an ``idaapi.tinfo_t`` and apply it to the function `func`.'''
        TINFO_GUESSED, TINFO_DEFINITE = getattr(idaapi, 'TINFO_GUESSED', 0), getattr(idaapi, 'TINFO_DEFINITE', 1)
        MANGLED_CODE, MANGLED_DATA, MANGLED_UNKNOWN = getattr(idaapi, 'MANGLED_CODE', 0), getattr(idaapi, 'MANGLED_DATA', 1), getattr(idaapi, 'MANGLED_UNKNOWN', 2)
        Fmangled_type = idaapi.get_mangled_name_type if hasattr(idaapi, 'get_mangled_name_type') else utils.fcompose(utils.frpartial(idaapi.demangle_name, 0), utils.fcondition(operator.truth)(0, MANGLED_UNKNOWN))
        MNG_NODEFINIT, MNG_NOPTRTYP, MNG_LONG_FORM = getattr(idaapi, 'MNG_NODEFINIT', 8), getattr(idaapi, 'MNG_NOPTRTYP', 7), getattr(idaapi, 'MNG_LONG_FORM', 0x6400007)
        til = idaapi.cvar.idati if idaapi.__version__ < 7.0 else idaapi.get_idati()

        # Figure out what we're actually going to be applying the type information to,
        # and figure out what its real name is so that we can mangle it if necessary.
        rt, ea = interface.addressOfRuntimeOrStatic(func)

        fname, mangled = name(ea), database.name(ea) if rt else utils.string.of(idaapi.get_func_name(ea))
        if fname and Fmangled_type(utils.string.to(mangled)) != MANGLED_UNKNOWN:
            realname = utils.string.of(idaapi.demangle_name(utils.string.to(mangled), MNG_NODEFINIT|MNG_NOPTRTYP) or fname)
        else:
            realname = fname

        # Now we can parse it and see what we have. If we couldn't parse it or it
        # wasn't an actual function of any sort, then we need to bail.
        ti = internal.declaration.parse(info)
        if not ti:
            raise E.InvalidTypeOrValueError(u"{:s}.info({:#x}, {!r}) : Unable to parse the provided string (\"{!s}\") into an actual type.".format('.'.join([__name__, cls.__name__]), ea, info, utils.string.escape(info, '"')))

        elif not any([ti.is_func(), ti.is_funcptr()]):
            raise E.InvalidTypeOrValueError("{:s}({:#x}, {!r}) : Refusing to apply a non-function type (\"{!s}\") to the given {:s} ({:#x}).".format('.'.join([__name__, cls.__name__]), ea, info, utils.string.escape(info, '"'), 'address' if rt else 'function', ea))

        # Otherwise, te type is valid and we only need to figure out if it needs
        # to be promoted to a pointer or not.
        if rt and not ti.is_funcptr():
            pi = idaapi.ptr_type_data_t()
            pi.obj_type = ti
            ti = idaapi.tinfo_t()
            if not ti.create_ptr(pi):
                raise E.DisassemblerError("{:s}({:#x}, {!r}) : Unable to promote type to a pointer due to being applied to a function pointer.".format('.'.join([__name__, cls.__name__]), ea, info))

            # Now we re-render it into a string so that it can be applied.
            logging.warning("{:s}({:#x}, {!r}) : Promoting type ({!r}) to a function pointer ({!r}) due to the address ({:#x}) being runtime-linked.".format('.'.join([__name__, cls.__name__]), ea, info, info, "{!s}".format(ti), ea))
            info = idaapi.print_tinfo('', 0, 0, 0, ti, utils.string.to(realname), '')

        # Terminate the typeinfo string with a ';' so that IDA can parse it.
        terminated = info if info.endswith(';') else "{:s};".format(info)

        # Now we should just be able to apply it to the function.
        result, ok = cls(ea), idaapi.apply_cdecl(til, ea, terminated, TINFO_DEFINITE)
        if not ok:
            raise E.InvalidTypeOrValueError(u"{:s}.info({:#x}) : Unable to apply the specified type declaration (\"{!s}\").".format('.'.join([__name__, cls.__name__]), ea, utils.string.escape(info, '"')))

        # since TINFO_GUESSED doesn't always work, we clear aflags here.
        if guessed.get('guessed', False):
            interface.node.aflags(ea, idaapi.AFL_USERTI, 0)
        return result
    @utils.multicase(none=None.__class__)
    def __new__(cls, func, none):
        '''Remove the type information for the function `func`.'''
        rt, ea = interface.addressOfRuntimeOrStatic(func)

        # If we're interacting with a runtime address, then it's just regular type
        # information and we can just assign empty type information to it.
        if rt:
            return database.type(ea, none)

        # All we need to do is just delete the type information from the address.
        if hasattr(idaapi, 'del_tinfo'):
            result, _ = cls(ea), idaapi.del_tinfo(ea)

        elif idaapi.__version__ < 7.0:
            result, _ = cls(ea), idaapi.del_tinfo2(ea)

        # We don't have a real way to remove the type information from a function,
        # but what we can do is remove the NSUP_TYPEINFO(3000) and clear the its aflags.
        else:
            supvals = [idaapi.NSUP_TYPEINFO, idaapi.NSUP_TYPEINFO + 1]
            aflags = [idaapi.AFL_TI, idaapi.AFL_USERTI, getattr(idaapi, 'AFL_HR_GUESSED_FUNC', 0x40000000), getattr(idaapi, 'AFL_HR_GUESSED_DATA', 0x80000000)]

            # Save the original type, and zero out everything. This should pretty much get it done...
            result, _  = cls(ea), interface.node.aflags(ea, functools.reduce(operator.or_, aflags), 0)
            [ internal.netnode.sup.remove(ea, val) for val in supvals ]
        return result

    @utils.multicase()
    @classmethod
    def flags(cls):
        '''Return the flags for the current function.'''
        return cls.flags(ui.current.function())
    @utils.multicase()
    @classmethod
    def flags(cls, func):
        '''Return the flags for the function `func`.'''
        fn = by(func)
        return idaapi.as_uint32(fn.flags)
    @utils.multicase(mask=six.integer_types)
    @classmethod
    def flags(cls, func, mask):
        '''Return the flags for the function `func` selected with the specified `mask`.'''
        fn = by(func)
        return idaapi.as_uint32(fn.flags & mask)
    @utils.multicase(mask=six.integer_types, integer=(bool, six.integer_types))
    @classmethod
    def flags(cls, func, mask, integer):
        '''Set the flags for the function `func` selected by the specified `mask` to the provided `integer`.'''
        fn, preserve, value = by(func), idaapi.as_uint32(~mask), idaapi.as_uint32(-1 if integer else 0) if isinstance(integer, bool) else idaapi.as_uint32(integer)
        res, fn.flags = fn.flags, (fn.flags & preserve) | (value & mask)
        if not idaapi.update_func(fn):
            description = ("{:#x}" if isinstance(func, six.integer_types) else "{!r}").format(func)
            logging.fatal(u"{:s}.flags({:s}, {:#x}, {!s}) : Unable to change the flags ({:#x}) for function at {:s} to requested value ({:#x}).".format('.'.join([__name__, cls.__name__]), description, mask, value, idaapi.as_uint32(res), description, idaapi.as_uint32(fn.flags)))
        return idaapi.as_uint32(res & mask)

    @utils.multicase()
    @classmethod
    def has_problem(cls):
        '''Return if the current function has a problem associated with it.'''
        return cls.has_problem(ui.current.address())
    @utils.multicase()
    @classmethod
    def has_problem(cls, func):
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
    @utils.multicase(problem=six.integer_types)
    @classmethod
    def has_problem(cls, func, problem):
        '''Return if the function `func` has the specified `problem` associated with it.'''
        PR_END = getattr(idaapi, 'PR_END', 17)
        iterable = (getattr(idaapi, attribute) for attribute in ['is_problem_present', 'QueueIsPresent'] if hasattr(idaapi, attribute))
        Fproblem = builtins.next(iterable, utils.fconstant(False))

        # Now we can just ask if the specified problem exists for the function.
        _, ea = interface.addressOfRuntimeOrStatic(func)
        return Fproblem(problem, ea)
    problem = problemQ = utils.alias(has_problem, 'type')

    @utils.multicase()
    @classmethod
    def is_decompiled(cls):
        '''Return if the current function has been decompiled.'''
        return cls.is_decompiled(ui.current.address())
    @utils.multicase()
    @classmethod
    def is_decompiled(cls, func):
        '''Return if the function `func` has been decompiled.'''
        AFL_HR_DETERMINED = getattr(idaapi, 'AFL_HR_DETERMINED', 0xc0000000)
        _, ea = interface.addressOfRuntimeOrStatic(func)
        return interface.node.aflags(ea, AFL_HR_DETERMINED)
    decompiled = decompiledQ = utils.alias(is_decompiled, 'type')

    @utils.multicase()
    @classmethod
    def has_frame(cls):
        '''Return if the current function has a frame allocated to it.'''
        return cls.has_frame(ui.current.function())
    @utils.multicase()
    @classmethod
    def has_frame(cls, func):
        '''Return if the function `func` has a frame allocated to it.'''
        fn = by(func)
        return fn.frame != idaapi.BADADDR
    frame = frameQ = utils.alias(has_frame, 'type')

    @utils.multicase()
    @classmethod
    def has_frameptr(cls):
        '''Return if the current function uses a frame pointer (register).'''
        return cls.has_frameptr(ui.current.function())
    @utils.multicase()
    @classmethod
    def has_frameptr(cls, func):
        '''Return if the function `func` uses a frame pointer (register).'''
        return True if cls.flags(func, idaapi.FUNC_FRAME) else False
    frameptr = frameptrQ = utils.alias(has_frameptr, 'type')

    @utils.multicase()
    @classmethod
    def has_name(cls):
        '''Return if the current function has a user-defined name.'''
        return cls.has_name(ui.current.address())
    @utils.multicase()
    @classmethod
    def has_name(cls, func):
        '''Return if the function `func` has a user-defined name.'''
        _, ea = interface.addressOfRuntimeOrStatic(func)
        return database.type.has_customname(ea)
    named = nameQ = customnameQ = has_customname = utils.alias(has_name, 'type')

    @utils.multicase()
    @classmethod
    def has_return(cls):
        '''Return if the current function returns.'''
        return cls.has_return(ui.current.function())
    @utils.multicase()
    @classmethod
    def has_return(cls, func):
        '''Return if the function `func` returns.'''
        fn = by(func)
        if fn.flags & idaapi.FUNC_NORET_PENDING == idaapi.FUNC_NORET_PENDING:
            logging.warning(u"{:s}.has_return({:s}) : Analysis for function return is still pending. The flag (`idaapi.FUNC_NORET_PENDING`) is still set.".format('.'.join([__name__, cls.__name__]), ("{:#x}" if isinstance(func, six.integer_types) else "{!r}").format(func)))
        return not (fn.flags & idaapi.FUNC_NORET == idaapi.FUNC_NORET)
    returns = returnQ = utils.alias(has_return, 'type')

    @utils.multicase()
    @classmethod
    def is_library(cls):
        '''Return a boolean describing whether the current function is considered a library function.'''
        return cls.is_library(ui.current.function())
    @utils.multicase()
    @classmethod
    def is_library(cls, func):
        '''Return a boolean describing whether the function `func` is considered a library function.'''
        return True if cls.flags(func, idaapi.FUNC_LIB) else False
    libraryQ = utils.alias(is_library, 'type')

    @utils.multicase()
    @classmethod
    def library(cls):
        '''Return a boolean describing whether the current function is considered a library function.'''
        return cls.is_library(ui.current.function())
    @utils.multicase()
    @classmethod
    def library(cls, func):
        '''Return a boolean describing whether the function `func` is considered a library function.'''
        return cls.is_library(func)
    @utils.multicase()
    @classmethod
    def library(cls, func, boolean):
        '''Modify the attributes of the function `func` to set it as a library function depending on the value of `boolean`.'''
        return cls.flags(func, idaapi.FUNC_LIB, -1 if boolean else 0) == idaapi.FUNC_LIB

    @utils.multicase()
    @classmethod
    def is_thunk(cls):
        '''Return a boolean describing whether the current function was determined to be a code thunk.'''
        return cls.is_thunk(ui.current.function())
    @utils.multicase()
    @classmethod
    def is_thunk(cls, func):
        '''Return a boolean describing whether the function `func` was determined to be a code thunk.'''
        return True if cls.flags(func, idaapi.FUNC_THUNK) else False
    thunkQ = utils.alias(is_thunk, 'type')

    @utils.multicase()
    @classmethod
    def thunk(cls):
        '''Return a boolean describing whether the current function was determined to be a code thunk.'''
        return cls.is_thunk(ui.current.function())
    @utils.multicase()
    @classmethod
    def thunk(cls, func):
        '''Return a boolean describing whether the function `func` was determined to be a code thunk.'''
        return cls.is_thunk(func)
    @utils.multicase()
    @classmethod
    def thunk(cls, func, boolean):
        '''Modify the attributes of the function `func` to set it as a code thunk depending on the value of `boolean`.'''
        return cls.flags(func, idaapi.FUNC_THUNK, -1 if boolean else 0) == idaapi.FUNC_THUNK

    @utils.multicase()
    @classmethod
    def is_far(cls):
        '''Return a boolean describing whether the current function is considered a "far" function by IDA or the user.'''
        return cls.is_far(ui.current.function())
    @utils.multicase()
    @classmethod
    def is_far(cls, func):
        '''Return a boolean describing whether the function `func` is considered a "far" function by IDA or the user.'''
        return True if cls.flags(func, idaapi.FUNC_FAR | idaapi.FUNC_USERFAR) else False
    far = farQ = utils.alias(is_far, 'type')

    @utils.multicase()
    @classmethod
    def is_static(cls):
        '''Return a boolean describing whether the current function is defined as a static function.'''
        return cls.is_static(ui.current.function())
    @utils.multicase()
    @classmethod
    def is_static(cls, func):
        '''Return a boolean describing whether the function `func` is defined as a static function.'''
        FUNC_STATICDEF = idaapi.FUNC_STATICDEF if hasattr(idaapi, 'FUNC_STATICDEF') else idaapi.FUNC_STATIC
        return True if cls.flags(func, FUNC_STATICDEF) else False
    staticQ = utils.alias(is_static, 'type')

    @utils.multicase()
    @classmethod
    def static(cls):
        '''Return a boolean describing whether the current function is defined as a static function.'''
        return cls.is_static(ui.current.function())
    @utils.multicase()
    @classmethod
    def static(cls, func):
        '''Return a boolean describing whether the function `func` is defined as a static function.'''
        return cls.is_static(func)
    @utils.multicase()
    @classmethod
    def static(cls, func, boolean):
        '''Modify the attributes of the function `func` to set it as a static function depending on the value of `boolean`.'''
        FUNC_STATICDEF = idaapi.FUNC_STATICDEF if hasattr(idaapi, 'FUNC_STATICDEF') else idaapi.FUNC_STATIC
        return cls.flags(func, FUNC_STATICDEF, -1 if boolean else 0) == FUNC_STATICDEF

    @utils.multicase()
    @classmethod
    def is_hidden(cls):
        '''Return a boolean describing whether the current function is hidden.'''
        return cls.is_hidden(ui.current.function())
    @utils.multicase()
    @classmethod
    def is_hidden(cls, func):
        '''Return a boolean describing whether the function `func` is hidden.'''
        return True if cls.flags(func, idaapi.FUNC_HIDDEN) else False
    hiddenQ = utils.alias(is_hidden, 'type')

    @utils.multicase()
    @classmethod
    def hidden(cls):
        '''Return a boolean describing whether the current function is hidden.'''
        return cls.is_hidden(ui.current.function())
    @utils.multicase()
    @classmethod
    def hidden(cls, func):
        '''Return a boolean describing whether the function `func` is hidden.'''
        return cls.is_hidden(func)
    @utils.multicase()
    @classmethod
    def hidden(cls, func, boolean):
        '''Modify the attributes of the function `func` to set it as a hidden function depending on the value of `boolean`.'''
        return cls.flags(func, idaapi.FUNC_HIDDEN, -1 if boolean else 0) == idaapi.FUNC_HIDDEN

    @utils.multicase()
    @classmethod
    def has_prototype(cls):
        '''Return a boolean describing whether the current function has a prototype associated with it.'''
        return cls.has_prototype(ui.current.address())
    @utils.multicase()
    @classmethod
    def has_prototype(cls, func):
        '''Return a boolean describing whether the function `func` has a prototype associated with it.'''
        _, ea = interface.addressOfRuntimeOrStatic(func)
        return database.type.has_typeinfo(ea)
    prototype = prototypeQ = has_typeinfo = typeinfoQ = utils.alias(has_prototype, 'type')

    @utils.multicase()
    @classmethod
    def convention(cls):
        '''Return the calling convention of the current function.'''
        # we avoid ui.current.function() so that we can also act on pointers.
        return cls.convention(ui.current.address())
    @utils.multicase()
    @classmethod
    def convention(cls, func):
        """Return the calling convention of the function `func`.

        The integer returned corresponds to one of the ``idaapi.CM_CC_*`` constants.
        """
        get_tinfo = (lambda ti, ea: idaapi.get_tinfo2(ea, ti)) if idaapi.__version__ < 7.0 else idaapi.get_tinfo
        try:
            _, ea = interface.addressOfRuntimeOrStatic(func)

        # If we couldn't resolve the function, then consider our parameter
        # as the calling convention that we're going to apply to the current address.
        except E.FunctionNotFoundError:
            return cls.convention(ui.current.address(), func)

        # Grab the type information from the address that we resolved. We avoid
        # doing any "guessing" here and only work with an explicitly applied type.
        ti = idaapi.tinfo_t()
        if not get_tinfo(ti, ea):
            raise E.MissingTypeOrAttribute(u"{:s}.convention({:#x}) : Specified function {:#x} does not contain a prototype declaration.".format('.'.join([__name__, cls.__name__]), ea, ea))

        # Now we can just grab the function details for this type, use it to extract
        # the convention and the spoiled count, and then return what we found.
        _, ftd = interface.tinfo.function_details(ea, ti)
        result, spoiled_count = ftd.cc & idaapi.CM_CC_MASK, ftd.cc & ~idaapi.CM_CC_MASK
        return result
    @utils.multicase(convention=six.string_types)
    @classmethod
    def convention(cls, func, convention):
        '''Set the calling convention used by the prototype for the function `func` to the specified `convention` string.'''
        cclookup = {
            '__cdecl': idaapi.CM_CC_CDECL,
            '__stdcall': idaapi.CM_CC_STDCALL,
            '__pascal': idaapi.CM_CC_PASCAL,
            '__fastcall': idaapi.CM_CC_FASTCALL,
            '__thiscall': idaapi.CM_CC_THISCALL,
        }

        # Try to normalize the string so that it will match an entry in our table.
        noncommonsuffix = {item for item in cclookup if not item.endswith('call')}
        prefixed = convention.lower() if convention.startswith('__') else "__{:s}".format(convention).lower()
        string = prefixed if operator.contains(noncommonsuffix, prefixed) or prefixed.endswith('call') else "{:s}call".format(prefixed)

        # FIXME: we should probably use globs, or something more intelligent
        #        to figure out what convention the user is trying apply.

        # Verify that the string can be found in our lookup table, and then use it to grab our cc.
        if not operator.contains(cclookup, string):
            raise E.ItemNotFoundError(u"{:s}.convention({!r}, {!r}) : The convention that was specified ({!r}) is not of the known types ({:s}).".format('.'.join([__name__, cls.__name__]), func, convention, string, ', '.join(cclookup)))
        cc = cclookup[string]

        # Now we have the calling convention integer that we can use.
        return cls.convention(func, cc)
    @utils.multicase(convention=six.integer_types)
    @classmethod
    def convention(cls, func, convention):
        '''Set the calling convention used by the prototype for the function `func` to the specified `convention`.'''
        _, ea = interface.addressOfRuntimeOrStatic(func)
        get_tinfo = (lambda ti, ea: idaapi.get_tinfo2(ea, ti)) if idaapi.__version__ < 7.0 else idaapi.get_tinfo

        # Grab the type information from the resolved address.
        ti = idaapi.tinfo_t()
        if not get_tinfo(ti, ea):
            raise E.MissingTypeOrAttribute(u"{:s}.convention({:#x}, {:#x}) : The specified function ({:#x}) does not contain a prototype declaration.".format('.'.join([__name__, cls.__name__]), ea, convention, ea))

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
        @utils.multicase(info=idaapi.tinfo_t)
        def __new__(cls, info):
            '''Modify the result type for the current function to the type information provided as an ``idaapi.tinfo_t`` provided in `info`.'''
            return cls(ui.current.address(), info)
        @utils.multicase()
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
        @utils.multicase(info=six.string_types)
        @utils.string.decorate_arguments('info')
        def __new__(cls, func, info):
            '''Modify the result type for the function `func` to the type information provided as a string in `info`.'''

            # FIXME: figure out the proper way to parse a type instead of as a declaration
            tinfo = internal.declaration.parse(info)
            if tinfo is None:
                raise E.InvalidTypeOrValueError(u"{:s}.result({!r}, {!r}) : Unable to parse the provided type information ({!r})".format('.'.join([__name__, cls.__name__]), func, info, info))
            return cls(func, tinfo)
        @utils.multicase(info=idaapi.tinfo_t)
        def __new__(cls, func, info):
            '''Modify the result type for the function `func` to the type information provided as an ``idaapi.tinfo_t`` in `info`.'''
            _, ea = interface.addressOfRuntimeOrStatic(func)
            get_tinfo = (lambda ti, ea: idaapi.get_tinfo2(ea, ti)) if idaapi.__version__ < 7.0 else idaapi.get_tinfo

            # Grab the type information from the function that we'll update with.
            ti = idaapi.tinfo_t()
            if not get_tinfo(ti, ea):
                raise E.MissingTypeOrAttribute(u"{:s}.result({:#x}, {!r}) : Specified function {:#x} does not contain a prototype declaration.".format('.'.join([__name__, cls.__name__]), ea, "{!s}".format(info), ea))

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
        @utils.multicase()
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
            if builtins.isinstance(result, builtins.tuple) and any(isinstance(item, interface.register_t) for item in result):
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

        @utils.multicase(index=six.integer_types)
        def __new__(cls, index):
            '''Return the type information for the parameter at the specified `index` of the current function.'''
            return cls(ui.current.address(), index)
        @utils.multicase(index=six.integer_types, info=(six.string_types, idaapi.tinfo_t))
        def __new__(cls, index, info):
            '''Modify the type information for the parameter at the specified `index` of the current function to `info`.'''
            return cls(ui.current.address(), index, info)
        @utils.multicase(index=six.integer_types)
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
        @utils.multicase(index=six.integer_types, info=idaapi.tinfo_t)
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
        @utils.multicase(index=six.integer_types, info=six.string_types)
        @utils.string.decorate_arguments('info')
        def __new__(cls, func, index, info):
            '''Modify the type information for the parameter at the specified `index` of the function `func` to the string in `info`.'''
            tinfo = internal.declaration.parse(info)
            if tinfo is None:
                raise E.InvalidTypeOrValueError(u"{:s}({!r}, {:d}, {!r}) : Unable to parse the provided type information ({!r}).".format('.'.join([__name__, cls.__name__]), func, index, info, info))
            return cls(func, index, tinfo)

        @utils.multicase(index=six.integer_types)
        @classmethod
        def name(cls, index):
            '''Return the name of the parameter at the specified `index` in the current function.'''
            return cls.name(ui.current.address(), index)
        @utils.multicase(index=six.integer_types, none=None.__class__)
        @classmethod
        def name(cls, index, none):
            '''Remove the name from the parameter at the specified `index` in the current function.'''
            return cls.name(ui.current.address(), index, none)
        @utils.multicase(index=six.integer_types, string=six.string_types)
        @classmethod
        def name(cls, index, string, *suffix):
            '''Modify the name of the parameter at the specified `index` of the current function to `string`.'''
            return cls.name(ui.current.address(), index, string, *suffix)
        @utils.multicase(index=six.integer_types)
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
        @utils.multicase(index=six.integer_types, none=None.__class__)
        @classmethod
        def name(cls, func, index, none):
            '''Remove the name from the parameter at the specified `index` in the function `func`.'''
            return cls.name(func, index, '')
        @utils.multicase(index=six.integer_types, string=six.string_types)
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

        @utils.multicase(index=six.integer_types)
        @classmethod
        def storage(cls, index):
            '''Return the storage location of the parameter at the specified `index` in the current function.'''
            return cls.storage(ui.current.address(), index)
        @utils.multicase(index=six.integer_types)
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
            if isinstance(location, builtins.tuple):
                reg, off = location
                if isinstance(off, six.integer_types) and off == 0:
                    return reg
                return location
            return location

        @utils.multicase(index=six.integer_types)
        @classmethod
        def remove(cls, index):
            '''Remove the parameter at the specified `index` from the current function.'''
            return cls.remove(ui.current.address(), index)
        @utils.multicase(index=six.integer_types)
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

        @utils.multicase(index=six.integer_types)
        @classmethod
        def location(cls, index):
            '''Return the address of the parameter at `index` that is passed to the function referenced at the current address.'''
            return cls.location(ui.current.address(), index)
        @utils.multicase(ea=six.integer_types, index=six.integer_types)
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
        @utils.multicase()
        def __new__(cls, func):
            '''Return the type information for each of the parameters belonging to the function `func`.'''
            _, ea = internal.interface.addressOfRuntimeOrStatic(func)
            ti = type(ea)

            # Use the address and type to snag the details requested by the
            # caller, iterate through it, and then return each type as a list.
            _, ftd = interface.tinfo.function_details(ea, ti)
            iterable = (ftd[index] for index in builtins.range(ftd.size()))
            return [item.type for item in iterable]
        @utils.multicase(types=(builtins.list, builtins.tuple))
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
                aname, ainfo = item if isinstance(item, builtins.tuple) else ('', item)
                ftd[index].name, ftd[index].type = utils.string.to(aname), internal.declaration.parse(ainfo) if isinstance(ainfo, six.string_types) else ainfo
            updater.send(ftd), updater.close()

            # The very last thing we need to do is to return our results. Even though we collected
            # all their information for safety, we return just the types for simplicity.
            return [item for _, item, _, _ in results]

        @utils.multicase()
        @classmethod
        def count(cls):
            '''Return the number of parameters in the prototype for the current function.'''
            return cls.count(ui.current.address())
        @utils.multicase()
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
        @utils.multicase()
        @classmethod
        def types(cls, func):
            '''Return the type information for each of the parameters belonging to the function `func`.'''
            return cls(func)
        @utils.multicase(types=(builtins.list, builtins.tuple))
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
        @utils.multicase()
        @classmethod
        def names(cls, func):
            '''Return the names for each of the parameters belonging to the function `func`.'''
            _, ea = internal.interface.addressOfRuntimeOrStatic(func)
            ti, ftd = interface.tinfo.function_details(ea, type(ea))

            # Iterate through the function details and return each name as a list.
            iterable = (ftd[index] for index in builtins.range(ftd.size()))
            return [utils.string.to(item.name) for item in iterable]
        @utils.multicase(names=(builtins.list, builtins.tuple))
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
        @utils.multicase()
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
        @utils.multicase()
        @classmethod
        def registers(cls, func):
            '''Return the registers for each of the parameters belonging to the function `func`.'''
            result = []
            for _, _, loc in cls.iterate(func):
                if isinstance(loc, builtins.tuple) and any(isinstance(item, interface.register_t) for item in loc):
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
        @utils.multicase()
        @classmethod
        def storage(cls, func):
            '''Return the storage locations for each of the parameters belonging to the function `func`.'''
            iterable = (location for _, _, location in cls.iterate(func))
            result = []
            for _, _, item in cls.iterate(func):
                if isinstance(item, builtins.tuple) and isinstance(item[1], six.integer_types):
                    register, offset = item
                    result.append(item if offset else register)
                else:
                    result.append(item)
                continue
            return result

        @utils.multicase(info=(six.string_types, idaapi.tinfo_t))
        @classmethod
        def add(cls, info):
            '''Add the provided type information in `info` as another parameter to the current function.'''
            return cls.add(ui.current.address(), info, '')
        @utils.multicase(info=(six.string_types, idaapi.tinfo_t))
        @classmethod
        def add(cls, func, info):
            '''Add the provided type information in `info` as another parameter to the function `func`.'''
            return cls.add(func, info, '')
        @utils.multicase(info=(six.string_types, idaapi.tinfo_t), name=six.string_types)
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
            res = name if isinstance(name, tuple) else (name,)
            aname, ainfo = interface.tuplename(*(res + suffix)), internal.declaration.parse(info) if isinstance(info, six.string_types) else info
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
        @utils.multicase(ea=six.integer_types)
        @classmethod
        def locations(cls, ea):
            '''Return the address of each of the parameters being passed to the function referenced at address `ea`.'''
            if not database.xref.code_down(ea):
                raise E.InvalidTypeOrValueError(u"{:s}.arguments({:#x}) : Unable to return any parameters as the provided address ({:#x}) {:s} code references.".format('.'.join([__name__, cls.__name__]), ea, ea, 'does not have any' if instruction.type.is_call(ea) else 'is not a call instruction with'))
            items = idaapi.get_arg_addrs(ea)
            return [] if items is None else [ea for ea in items]
        @utils.multicase(ea=six.integer_types)
        @classmethod
        def locations(cls, func, ea):
            '''Return the address of each of the parameters for the function `func` that are being passed to the function referenced at address `ea`.'''
            refs = {ref for ref in cls.up(func)}
            if ea not in refs:
                logging.warning(u"{:s}.arguments({!r}, {:#x}) : Ignoring the provided function ({:#x}) as the specified reference ({:#x}) is not referring to it.".format('.'.join([__name__, cls.__name__]), func, ea, address(func), ea))
            return cls.locations(ea)
        location = utils.alias(locations, 'type.arguments')

    args = parameters = arguments

t = type # XXX: ns alias
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
        > for ea in function.xref.down(): ...

    """

    ## referencing
    @utils.multicase()
    @classmethod
    def down(cls, **references):
        '''Return all of the addresses that are referenced by a branch instruction from the current function.'''
        return down(ui.current.function(), **references)
    @utils.multicase()
    @classmethod
    def down(cls, func, **references):
        """Return all of the addresses that are referenced by a branch instruction from the function `func`.

        If the boolean `references` is true, then include the reference address of each instruction along with its.
        """
        get_switch_info = idaapi.get_switch_info_ex if idaapi.__version__ < 7.0 else idaapi.get_switch_info

        # define a closure that will get us all of the related code references so we can process them.
        def Freferences(fn):
            branches = [instruction.is_call, instruction.is_branch]
            for ea in iterate(fn):

                # if it isn't code, then we skip it.
                if not database.type.is_code(ea):
                    continue

                # if it's a branching or call-type instruction that has no xrefs, then log a warning for the user.
                elif not len(database.xref.down(ea)) and any(F(ea) for F in branches):
                    logging.warning(u"{:s}.down({:#x}) : Discovered the \"{:s}\" instruction at {:#x} that might've contained a reference but was unresolved.".format('.'.join([__name__, cls.__name__]), interface.range.start(fn), utils.string.escape(database.instruction(ea), '"'), ea))
                    continue

                # now we need to check which code xrefs are actually going to be something we care
                # about by checking to see if there's an xref pointing outside our function.
                for xref in filter(database.within, database.xref.code_down(ea)):
                    if not contains(fn, xref):
                        yield ea, xref

                    # if it's a branching or call-type instruction, but referencing non-code, then we care about it.
                    elif not database.type.is_code(xref) and any(F(ea) for F in branches):
                        yield ea, xref

                    # if we're recursive and there's a code xref that's referencing our entrypoint,
                    # then we're going to want that too.
                    elif interface.range.start(fn) == xref:
                        yield ea, xref
                    continue

                # if we're at a switch branch, then we don't need to follow any
                # data references, and we can just skip the rest of our logic.
                if get_switch_info(ea):
                    continue

                # last thing we need to determine is which data xrefs are relevant
                # which only includes things that reference code outside of us.
                for xref in filter(database.within, database.xref.data_down(ea)):
                    if database.type.is_code(xref) and not contains(fn, xref):
                        yield ea, xref

                    # if it's referencing an external, then yeah...this is definitely an xref we want.
                    elif idaapi.segtype(xref) in {idaapi.SEG_XTRN}:
                        # FIXME: technically an external could also be a non-callable address, but we
                        #        don't care because the user is gonna wanna know about it anyways.
                        yield ea, xref

                    # otherwise if it's a branch, but not referencing any code
                    # then this is probably a global containing a code pointer.
                    elif not database.type.is_code(xref) and any(F(ea) for F in branches):
                        yield ea, xref
                    continue
                continue
            return

        # grab our function and then grab all of the references from it.
        fn = by(func)
        iterable = Freferences(fn)

        # now we need to figure out if we're just going to return the referenced addresses.
        if not builtins.next((references[k] for k in ['reference', 'references', 'refs'] if k in references), False):
            return sorted({d for _, d in iterable})

        # otherwise we're being asked to return the source with its target reference for each one.
        results = {ea : d for ea, d in iterable}
        return [(ea, results[ea]) for ea in sorted(results)]

    @utils.multicase()
    @classmethod
    def up(cls):
        '''Return all of the addresses that reference the current function.'''
        return up(ui.current.address())
    @utils.multicase()
    @classmethod
    def up(cls, func):
        '''Return all of the addresses that reference the function `func`.'''
        rt, ea = interface.addressOfRuntimeOrStatic(func)
        # runtime
        if rt:
            return database.xref.up(ea)
        # regular
        return database.xref.up(ea)

    @utils.multicase(index=six.integer_types)
    @classmethod
    def argument(cls, index):
        '''Return the address of the parameter being passed to the function reference at the current address for the specified `index`.'''
        items = cls.arguments(ui.current.address())
        return items[index]
    @utils.multicase(index=six.integer_types, ea=six.integer_types)
    @classmethod
    def argument(cls, index, ea):
        '''Return the address of the parameter being passed to the function reference at the address `ea` for the specified `index`.'''
        items = cls.arguments(ea)
        return items[index]
    @utils.multicase(index=six.integer_types, ea=six.integer_types)
    @classmethod
    def argument(cls, func, index, ea):
        '''Return the address of the parameter from the specified `index` of the function `func` that is being passed to the function reference at the address `ea`.'''
        items = cls.arguments(func, ea)
        return items[index]
    arg = utils.alias(argument, 'xref')

    @utils.multicase()
    @classmethod
    def arguments(cls):
        '''Return the address of each of the parameters being passed to the function reference at the current address.'''
        return cls.arguments(ui.current.address())
    @utils.multicase(ea=six.integer_types)
    @classmethod
    def arguments(cls, ea):
        '''Return the address of each of the parameters being passed to the function reference at address `ea`.'''
        if not database.xref.code_down(ea):
            raise E.InvalidTypeOrValueError(u"{:s}.arguments({:#x}) : Unable to return any parameters as the provided address ({:#x}) {:s} code references.".format('.'.join([__name__, cls.__name__]), ea, ea, 'does not have any' if instruction.type.is_call(ea) else 'is not a call instruction with'))
        items = idaapi.get_arg_addrs(ea)
        return [] if items is None else [ea for ea in items]
    @utils.multicase(ea=six.integer_types)
    @classmethod
    def arguments(cls, func, ea):
        '''Return the address of each of the parameters for the function `func` that are being passed to the function reference at address `ea`.'''
        refs = {ref for ref in cls.up(func)}
        if ea not in refs:
            logging.warning(u"{:s}.arguments({!r}, {:#x}) : Ignoring the provided function ({:#x}) as the specified reference ({:#x}) is not referring to it.".format('.'.join([__name__, cls.__name__]), func, ea, address(func), ea))
        return cls.arguments(ea)
    args = utils.alias(arguments, 'xref')

x = xref    # XXX: ns alias
up, down = utils.alias(xref.up, 'xref'), utils.alias(xref.down, 'xref')
