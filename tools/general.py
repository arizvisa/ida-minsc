"""
General module

This module provides generalized tools that a user may find
useful in their reversing adventures. This includes classes
for performing address translations, coloring marks or tags,
recursively walking through basic blocks until a sentinel
block has been reached, or even recursively walking a
function's childrens until a particular sentinel function
is encountered.

The tools defined within here are unorganized and pretty
much unmaintained. Thus they may shift around during their
existence as they eventually find their place.
"""

import six, sys, logging, builtins
import functools, operator, itertools, types
import logging

import database, function as func, instruction, segment
import ui, internal

@document.parameters(F='the callback to execute on each function', kwargs='any extra arguments to pass to the callback')
def map(F, **kwargs):
    """Execute the callback `F` on all functions in the database. Synonymous to `map(F, database.functions())` but with some extra logging to display the current progress.

    The `F` parameter is defined as a function taking either an
    `(address, **kwargs)` or a `(index, address, **kwargs)`. Any
    keyword arguments are passed to `F` unmodified.
    """
    f1 = lambda idx, ea, **kwargs: F(ea, **kwargs)
    f2 = lambda idx, ea, **kwargs: F(idx, ea, **kwargs)
    Ff = internal.utils.pycompat.method.function(F) if isinstance(F, types.MethodType) else F
    Fc = internal.utils.pycompat.function.code(Ff)
    f = f1 if internal.utils.pycompat.code.argcount(Fc) == 1 else f2

    result, all = [], database.functions()
    total = len(all)
    if len(all):
        ea = next(item for item in all)
        try:
            for i, ea in enumerate(all):
                ui.navigation.set(ea)
                six.print_("{:#x}: processing # {:d} of {:d} : {:s}".format(ea, 1 + i, total, func.name(ea)))
                result.append( f(i, ea, **kwargs) )
        except KeyboardInterrupt:
            six.print_("{:#x}: terminated at # {:d} of {:d} : {:s}".format(ea, 1 + i, total, func.name(ea)))
    return result

# For poor folk without a dbgeng
@document.classdef
class remote(object):
    """
    An object that can be used to translate addresses to and from
    a debugging target so that one does not need to rebase their
    entire database, or come up with some other tricks to translate
    a binary address to its runtime address.
    """
    @document.parameters(remote='the remote address to translate to', local='the address to translate from. if none was specified then use the base address from the current database.')
    def __init__(self, remote, local=None):
        """Create a new instance with the specified `remote` base address.

        If `local` is not specified, then use the current database's base
        address for performing calculations.
        """
        if local is None:
            local = database.config.baseaddress()
        self.lbase = local
        self.rbase = remote

    @document.parameters(ea='a remote address to convert to the database address')
    def get(self, ea):
        '''Translate a remote address to the local database address.'''
        offset = ea - self.rbase
        return offset + self.lbase

    @document.parameters(ea='the local address in the database to convert to a remote one')
    def put(self, ea):
        '''Translate a local database address to the remote address.'''
        offset = ea - self.lbase
        return offset + self.rbase

    @document.parameters(ea='the remote address to seek to in the database')
    def go(self, ea):
        '''Seek the database to the specified remote address.'''
        res = self.get(ea)
        database.go(res)

## XXX: would be useful to have a quick wrapper class for interacting with Ida's mark list
##          in the future, this would be abstracted into a arbitrarily sized tree.

@document.parameters(color='the rgb color value to color each mark address with')
def colormarks(color=0x7f007f):
    """Walk through the current list of marks whilst coloring them with the specified `color`.

    Each mark's address is tagged with its description, and if the
    address belongs to a function, the function is also tagged with the
    address of the marks that it contains.
    """
    # tag and color
    f = {item for item in []}
    for ea, m in database.marks():
        database.tag(ea, 'mark', m)
        if database.color(ea) is None:
            database.color(ea, color)
        try:
            f.add(func.top(ea))
        except internal.exceptions.FunctionNotFoundError:
            pass
        continue

    # tag the functions too
    for ea in f:
        m = func.marks(ea)
        func.tag(ea, 'marks', [ea for ea, _ in m])
    return

def recovermarks():
    """Walk through the tags made by ``colormarks`` and re-create the marks that were found.

    This is useful if any marks were accidentally deleted and can be used for
    recovering them as long as they were initally tagged properly.
    """
    # collect
    result = []
    for fn, l in database.select('marks'):
        m = {item for item in l['marks']} if hasattr(l['marks'], '__iter__') else {int(item, 16) for item in l['marks'].split(',')} if isinstance(l['marks'], six.string_types) else {l['marks']}
        res = [(ea, d['mark']) for ea, d in func.select(fn, 'mark')]
        if m != { ea for ea, _ in res }:
            logging.warning("{:s} : Ignoring the function tag \"{:s}\" for function {:#x} due to its value being out-of-sync with the contents values ({!s} <> {!s}).".format('.'.join([__name__, 'recovermarks']), fn, builtins.map("{:#x}".format, m), builtins.map("{:#x}".format, {ea for ea, _ in res})))
        result.extend(res)
    result.sort(key=lambda item: item[1])

    # discovered marks versus database marks
    result = {ea : item for ea, item in result.items()}
    current = {ea : descr for ea, descr in database.marks()}

    # create tags
    for x, y in result.items():
        if x in current:
            logging.warning("{:#x}: skipping already existing mark : {!r}".format(x, current[x]))
            continue

        # x not in current
        if x not in current:
            logging.info("{:#x}: adding missing mark due to tag : {!r}".format(x, result[x]))
        elif current[x] != result[x]:
            logging.info("{:#x}: database tag is different than mark description : {!r}".format(x, result[x]))
        else:
            assert current[x] == result[x]
        database.mark(x, y)

    # marks that aren't reachable in the database
    for ea in { item for item in current.keys() }.difference({item for item in result.keys()}):
        logging.warning("{:#x}: unreachable mark (global) : {!r}".format(ea, current[ea]))

    # color them
    colormarks()

def checkmarks():
    """Emit all functions that contain more than 1 mark within them.

    As an example, if marks are used to keep track of backtraces then
    this tool will emit where those backtraces intersect.
    """
    listable = []
    for a, m in database.marks():
        try:
            listable.append((func.top(a), a, m))
        except internal.exceptions.FunctionNotFoundError:
            pass
        continue

    d = listable[:]
    d.sort(key=lambda item: item[0])

    flookup = {}
    for fn, a, m in d:
        try:
            flookup[fn].append((a, m))
        except:
            flookup[fn] = [(a, m)]
        continue

    functions = [ (k, v) for k, v in flookup.items() if len(v) > 1 ]
    if not functions:
        logging.warning('There are no functions available containing multiple marks.')
        return

    for k, v in functions:
        six.print_("{:#x} : in function {:s}".format(k, func.name(func.by_address(k))), file=sys.stdout)
        six.print_('\n'.join(("- {:#x} : {:s}".format(a, m) for a, m in sorted(v))), file=sys.stdout)
    return

@document.parameters(ea='the address of the basic block to start at', sentinel='an iterable containing the addresses of any basic blocks to terminate at')
def collect(ea, sentinel):
    """Collect all the basic blocks starting at address `ea` and recurse until a terminating block is encountered.

    If the set `sentinel` is specified, then its addresses are used as
    sentinel blocks and collection will terminate when those blocks are
    reached.
    """
    if isinstance(sentinel, (list, tuple)):
        sentinel = {item for item in sentinel}
    if not all((sentinel, isinstance(sentinel, set))):
        raise AssertionError("{:s}.collect({:#x}, {!r}) : Sentinel is empty or not a set.".format(__name__, ea, sentinel))
    def _collect(addr, result):
        process = {item for item in []}
        for blk in builtins.map(func.block, func.block.after(addr)):
            if any(blk in coll for coll in [result, sentinel]):
                continue
            process.add(blk)
        for addr, _ in process:
            result |= _collect(addr, result | process)
        return result
    addr, _ = blk = func.block(ea)
    return _collect(addr, {blk})

@document.parameters(ea='the address of the function to start from', sentinel='an iterable containing the addresses belonging to a functions to terminate at')
def collectcall(ea, sentinel=set()):
    """Collect all of the function calls starting at function `ea` and recurse until a terminating function is encountered.

    If the set `sentinel` is specified, then its addresses are used as
    sentinel functions and collection will terminate when one of those
    functions are reached.
    """
    if isinstance(sentinel, (list, tuple)):
        sentinel = {item for item in sentinel}
    if not isinstance(sentinel, set):
        raise AssertionError("{:s}.collectcall({:#x}, {!r}) : Sentinel is not a set.".format(__name__, ea, sentinel))
    def _collectcall(addr, result):
        process = {item for item in []}
        for f in func.down(addr):
            if any(f in coll for coll in [result, sentinel]):
                continue
            if not func.within(f):
                logging.warning("{:s}.collectcall({:#x}, {!r}) : Adding non-function address {:#x} ({:s}).".format(__name__, ea, sentinel, f, database.name(f)))
                result.add(f)
                continue
            process.add(f)
        for addr in process:
            result |= _collectcall(addr, result | process)
        return result
    addr = func.top(ea)
    return _collectcall(addr, {addr})

# FIXME: Don't emit the +0 if offset is 0
@document.parameters(ea='the address of the function to output calls to', includeSegment='whether to include the segment name in the output')
def above(ea, includeSegment=False):
    '''Return all of the function names and their offset that calls the function at `ea`.'''
    tryhard = lambda ea: "{:s}{:+x}".format(func.name(func.top(ea)), ea - func.top(ea)) if func.within(ea) else "{:+x}".format(ea) if func.name(ea) is None else func.name(ea)
    return '\n'.join(':'.join([segment.name(ea), tryhard(ea)] if includeSegment else [tryhard(ea)]) for ea in func.up(ea))

# FIXME: Don't emit the +0 if offset is 0
@document.parameters(ea='the address of the function to output calls from', includeSegment='whether to include the segment name in the output')
def below(ea, includeSegment=False):
    '''Return all of the function names and their offset that are called by the function at `ea`.'''
    tryhard = lambda ea: "{:s}{:+x}".format(func.name(func.top(ea)), ea - func.top(ea)) if func.within(ea) else "{:+x}".format(ea) if func.name(ea) is None else func.name(ea)
    return '\n'.join(':'.join([segment.name(ea), tryhard(ea)] if includeSegment else [tryhard(ea)]) for ea in func.down(ea))

# FIXME: this only works on x86 where args are pushed via stack
@document.parameters(ea='the address of a call instruction', target='the address that the call instruction branches to')
def makecall(ea=None, target=None):
    """Output the function call at `ea` and its arguments with the address they originated from.

    If `target` is specified, then assume that the instruction is
    calling `target` instead of the target address that the call
    is referencing.
    """
    ea = current.address() if ea is None else ea
    if not func.contains(ea, ea):
        return None

    if database.config.bits() != 32:
        raise RuntimeError("{:s}.makecall({!r}, {!r}) : Unable to determine arguments for {:s} due to {:d}-bit calling convention.".format(__name__, ea, target, database.disasm(ea), database.config.bits()))

    if target is None:
        # scan down until we find a call that references something
        chunk, = ((l, r) for l, r in func.chunks(ea) if l <= ea <= r)
        result = []
        while (len(result) < 1) and ea < chunk[1]:
            # FIXME: it's probably not good to just scan for a call
            if not database.instruction(ea).startswith('call '):
                ea = database.next(ea)
                continue
            result = database.cxdown(ea)
            if len(result) == 0: raise TypeError("{:s}.makecall({!r}, {!r}) : Unable to determine number of arguments.".format(__name__, ea, target))

        if len(result) != 1:
            raise ValueError("{:s}.makecall({!r}, {!r}) : An invalid number of targets was returned for the call at {:#x}. The call targets that were returned are {!r}.".format(__name__, ea, result))
        fn, = result
    else:
        fn = target

    try:
        result = []
        for offset, name, size in func.arguments(fn):
            left = database.address.prevstack(ea, offset + database.config.bits() // 8)
            # FIXME: if left is not an assignment or a push, find last assignment
            result.append((name, left))
    except internal.exceptions.OutOfBoundsError:
        raise internal.exceptions.OutOfBoundserror("{:s}.makecall({!r}, {!r}) : Unable to get arguments for target function.".format(__name__, ea, target))

    # FIXME: replace these crazy list comprehensions with something more comprehensible.
#    result = ["{:s}={:s}".format(name, instruction.op_repr(ea, 0)) for name, ea in result]
    result = ["({:#x}){:s}={:s}".format(ea, name, ':'.join(instruction.op_repr(database.address.prevreg(ea, instruction.op_value(ea, 0), write=True), n) for n in instruction.opsi_read(database.address.prevreg(ea, instruction.op_value(ea, 0), write=True))) if instruction.op_type(ea, 0) == 'reg' else instruction.op_repr(ea, 0)) for name, ea in result]

    try:
        return "{:s}({:s})".format(internal.declaration.demangle(func.name(func.by_address(fn))), ','.join(result))
    except:
        pass
    return "{:s}({:s})".format(internal.declaration.demangle(database.name(fn)), ','.join(result))
