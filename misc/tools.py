import six, sys, logging
from six.moves import builtins

import functools, operator, itertools, types
import logging

import database, function as func, instruction
import ui, internal

class remote(object):
    '''For poor folk without a dbgeng'''
    def __init__(self, remotebaseaddress, localbaseaddress=None):
        if localbaseaddress is None:
            localbaseaddress = database.config.baseaddress()
        self.lbase = localbaseaddress
        self.rbase = remotebaseaddress

    def get(self, ea):
        offset = ea - self.rbase
        return offset + self.lbase

    def put(self, ea):
        offset = ea - self.lbase
        return offset + self.rbase

    def go(self, ea):
        res = self.get(ea)
        database.go(res)

## XXX: would be useful to have a quick wrapper class for interacting with Ida's mark list
##          in the future, this would be abstracted into a arbitrarily sized tree.

def colormarks(color=0x7f007f):
    '''Iterate through all database marks and tag+color their address'''
    # tag and color
    f = set()
    for ea,m in database.marks():
        database.tag(ea, 'mark', m)
        if database.color(ea) is None:
            database.color(ea, color)
        try: f.add(func.top(ea))
        except (LookupError,ValueError): pass

    # tag the functions too
    for ea in list(f):
        m = func.marks(ea)
        func.tag(ea, 'marks', [ea for ea,_ in m])
    return

def recovermarks():
    '''Utilizing any tag information found in the database, recreate all the database marks.'''
    # collect
    result = []
    for fn,l in database.select('marks'):
        m = set( (l['marks']) if hasattr(l['marks'],'__iter__') else [int(x,16) for x in l['marks'].split(',')] if type(l['marks']) is str else [l['marks']])
        res = [(ea,d['mark']) for ea,d in func.select(fn,'mark')]
        if m != set(a for a,_ in res):
            logging.warning("{:#x}: ignoring cached version of marks due to being out-of-sync with real values : {!r} : {!r}".format(fn, builtins.map(hex,m), builtins.map(hex,set(a for a,_ in res))))
        result.extend(res)
    result.sort(cmp=lambda x,y: cmp(x[1],y[1]))

    # discovered marks versus database marks
    result = dict(result)
    current = {ea:descr for ea,descr in database.marks()}

    # create tags
    for x,y in result.items():
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
    for ea in set(current.viewkeys()).difference(result.viewkeys()):
        logging.warning("{:#x}: unreachable mark (global) : {!r}".format(ea, current[ea]))

    # color them
    colormarks()

def checkmarks():
    '''Output all functions (sys.stdout) containing more than 1 mark.'''
    res = []
    for a,m in database.marks():
        try:
            res.append((func.top(a), a, m))
        except ValueError:
            pass
        continue

    d = list(res)
    d.sort( lambda a,b: cmp(a[0], b[0]) )

    flookup = {}
    for fn,a,m in d:
        try:
            flookup[fn].append((a,m))
        except:
            flookup[fn] = [(a,m)]
        continue

    functions = [ (k,v) for k,v in flookup.items() if len(v) > 1 ]
    if not functions:
        logging.warning('There are no functions available containing multiple marks.')
        return

    for k,v in functions:
        print >>sys.stdout, "{:#x} : in function {:s}".format(k, func.name(func.byAddress(k)))
        print >>sys.stdout, '\n'.join( ("- {:#x} : {:s}".format(a,m) for a,m in sorted(v)) )
    return

def collect(ea, sentinel):
    '''Collect all the basic-blocks starting at address ``ea`` and terminating when an address in the set ``sentinel`` is reached.'''
    if isinstance(sentinel, list):
        sentinel = set(sentinel)
    if not all((sentinel, isinstance(sentinel, set))):
        raise AssertionError("{:s}.collect({:#x}, {!r}) : Sentinel is empty or not a set.".format(__name__, ea, sentinel))
    def _collect(addr, result):
        process = set()
        for blk in builtins.map(func.block, func.block.after(addr)):
            if any(blk in coll for coll in (result, sentinel)):
                continue
            process.add(blk)
        for addr, _ in process:
            result |= _collect(addr, result | process)
        return result
    addr, _ = blk = func.block(ea)
    return _collect(addr, set([blk]))

def collectcall(ea, sentinel=set()):
    '''Collect all the children functions starting at function ``ea`` and terminating when a function in the set ``sentinel`` is reached.'''
    if isinstance(sentinel, list):
        sentinel = set(sentinel)
    if not isinstance(sentinel, set):
        raise AssertionError("{:s}.collectcall({:#x}, {!r}) : Sentinel is not a set.".format(__name__, ea, sentinel))
    def _collectcall(addr, result):
        process = set()
        for f in func.down(addr):
            if any(f in coll for coll in (result, sentinel)):
                continue
            if not func.within(f):
                logging.warn("{:s}.collectcall({:#x}, {!r}) : Adding non-function address {:#x} ({:s}).".format(__name__, ea, sentinel, f, database.name(f)))
                result.add(f)
                continue
            process.add(f)
        for addr in process:
            result |= _collectcall(addr, result | process)
        return result
    addr = func.top(ea)
    return _collectcall(addr, set([addr]))

def above(ea, includeSegment=False):
    '''Display all the callers of the function at /ea/'''
    tryhard = lambda ea: "{:s}{:+x}".format(func.name(func.top(ea)),ea-func.top(ea)) if func.within(ea) else "{:+x}".format(ea) if func.name(ea) is None else func.name(ea)
    return '\n'.join(':'.join((segment.name(ea),tryhard(ea)) if includeSegment else (tryhard(ea),)) for ea in func.up(ea))

def below(ea, includeSegment=False):
    '''Display all the functions that the function at /ea/ can call'''
    tryhard = lambda ea: "{:s}{:+x}".format(func.name(func.top(ea)),ea-func.top(ea)) if func.within(ea) else "{:+x}".format(ea) if func.name(ea) is None else func.name(ea)
    return '\n'.join(':'.join((segment.name(ea),tryhard(ea)) if includeSegment else (tryhard(ea),)) for ea in func.down(ea))

# FIXME: this only works on x86 where args are pushed via stack
def makecall(ea=None, target=None):
    """Output the function call at ``ea`` and its arguments in C-form.

    If ``target`` is specified, then assume that the instruction is calling ``target``.
    """
    ea = current.address() if ea is None else ea
    if not func.contains(ea, ea):
        return None

    if database.config.bits() != 32:
        raise RuntimeError("{:s}.makecall({!r},{!r}) : Unable to determine arguments for {:s} due to {:d}-bit calling convention.".format(__name__, ea, target, database.disasm(ea), database.config.bits()))

    if target is None:
        # scan down until we find a call that references something
        chunk, = ((l,r) for l,r in func.chunks(ea) if l <= ea <= r)
        result = []
        while (len(result) < 1) and ea < chunk[1]:
            # FIXME: it's probably not good to just scan for a call
            if not database.instruction(ea).startswith('call '):
                ea = database.next(ea)
                continue
            result = database.cxdown(ea)
            if len(result) == 0: raise TypeError("{:s}.makecall({!r},{!r}) : Unable to determine number of arguments".format(__name__, ea, target))

        if len(result) != 1:
            raise ValueError("{:s}.makecall({!r},{!r}) : Too many targets for call at {:#x} : {!r}".format(__name__, ea, result))
        fn, = result
    else:
        fn = target

    try:
        result = []
        for offset,name,size in func.arguments(fn):
            left = database.address.prevstack(ea, offset+database.config.bits()/8)
            # FIXME: if left is not an assignment or a push, find last assignment
            result.append((name,left))
    except LookupError:
        raise LookupError("{:s}.makecall({!r},{!r}) : Unable to get arguments for target function".format(__name__, ea, target))

    # FIXME: replace these crazy list comprehensions with something more comprehensible.
#    result = ["{:s}={:s}".format(name,instruction.op_repr(ea, 0)) for name,ea in result]
    result = ["({:#x}){:s}={:s}".format(ea, name, ':'.join(instruction.op_repr(database.address.prevreg(ea, instruction.op_value(ea,0), write=1), n) for n in instruction.ops_read(database.address.prevreg(ea, instruction.op_value(ea,0), write=1))) if instruction.op_type(ea,0) == 'reg' else instruction.op_repr(ea, 0)) for name,ea in result]

    try:
        return "{:s}({:s})".format(internal.declaration.demangle(func.name(func.by_address(fn))), ','.join(result))
    except:
        pass
    return "{:s}({:s})".format(internal.declaration.demangle(database.name(fn)), ','.join(result))

def source(ea, *regs):
    '''Return the addresses and which specific operands write to the specified regs'''
    res = []
    for r in regs:
        pea = database.address.prevreg(ea, r, write=1)
        res.append( (pea,tuple(instruction.ops_read(pea))) )
    return res

def sourcechain(fn, *args, **kwds):
#    sentinel = kwds.get('types', set(('imm','phrase','addr','void')))
    sentinel = kwds.get('types', set(('imm','addr','void')))

    # XXX: was this supposed to be a linked list of relationships
    #      to the top of a function?
    result = {}
    for ea,opi in source(*args):
        if not func.contains(fn, ea): continue
        opt = tuple(instruction.op_type(ea,i) for i in opi)
        for i,t in zip(opi,opt):
            if t in sentinel:
                result.setdefault(ea,set()).add(i)
            elif t in {'reg'}:
                result.setdefault(ea,set()).add(i)
                r = instruction.op_value(ea,i)
                for a,b in sourcechain(fn, ea, r):
                    builtins.map(result.setdefault(a,set()).add, b)
            elif t in {'phrase'}:
                result.setdefault(ea,set()).add(i)
                _,(r1,r2,_) = instruction.op_value(ea,i)
                for a,b in sourcechain(fn, ea, *tuple(r for r in (r1, r2) if r is not None)):
                    builtins.map(result.setdefault(a,set()).add, b)
            elif t in {'imm', 'addr'}:
                result.setdefault(ea,set()).add(i)
            else:
                raise ValueError, (t, ea, i)
            continue
        continue
    return [(ea, result[ea]) for ea in sorted(six.viewkeys(result))]

def map(F, **kwargs):
    """Execute provided callback on all functions in database. Synonymous to map(F, database.functions()).

    ``F`` is defined as a function(address, **kwargs) or function(index, address, **kwargs).
    Any extra arguments are passed to ``F`` unmodified.
    """
    f1 = lambda (idx,ea), **kwargs: F(ea, **kwargs)
    f2 = lambda (idx,ea), **kwargs: F(idx, ea, **kwargs)
    f = f1 if F.func_code.co_argcount == 1 else f2

    result, all = [], database.functions()
    total = len(all)
    if len(all):
        ea = next(iter(all))
        try:
            for i, ea in enumerate(all):
                ui.navigation.set(ea)
                print("{:#x}: processing # {:d} of {:d} : {:s}".format(ea, i+1, total, func.name(ea)))
                result.append( f((i, ea), **kwargs) )
        except KeyboardInterrupt:
            print("{:#x}: terminated at # {:d} of {:d} : {:s}".format(ea, i+1, total, func.name(ea)))
    return result

# XXX: This namespace should be deprecated
class function(object):
    """
    Tools for iterating through a function looking for a match of some kind.
    """

    @internal.utils.multicase(regex=six.string_types)
    @classmethod
    def regex(cls, regex):
        '''Return each instruction in the current function that matches the string ``regex``.'''
        return cls.regex(ui.current.function(), regex)
    @internal.utils.multicase(regex=six.string_types)
    @classmethod
    def regex(cls, function, regex):
        '''Return each instruction in the ``function`` that matches the string ``regex``.'''
        pattern = re.compile(regex, re.I)
        for ea in func.iterate(function):
            insn = re.sub(' +', ' ', database.instruction(ea))
            if pattern.search(insn) is not None:
                yield ea
            continue
        return

    @internal.utils.multicase(match=(types.FunctionType, types.MethodType))
    @classmethod
    def instruction(cls, predicate):
        '''Search through the current function for any instruction that matches with the callable ``predicate``.'''
        return cls.instruction(ui.current.address(), predicate)
    @internal.utils.multicase(match=(types.FunctionType, types.MethodType))
    @classmethod
    def instruction(cls, function, predicate):
        """Search through the function ``function`` for any instruction that matches with the callable ``predicate``.

        ``predicate`` is a callable that takes one argument which is the result of database.instruction(ea).
        """
        for ea in func.iterate(function):
            res = database.instruction(ea)
            if predicate(res):
                yield ea
            continue
        return

    @classmethod
    def address(cls, predicate):
        '''Search through the current function for any address that matches with the callable ``predicate``.'''
        return cls.instruction(ui.current.address(), predicate)
    @internal.utils.multicase(match=(types.FunctionType, types.MethodType))
    @classmethod
    def address(cls, function, predicate):
        """Search through the ``function`` for any address that matches with the callable ``predicate``.

        ``predicate`` is a callable that takes one argument which is passed the address to match.
        """
        for ea in func.iterate(function):
            if predicate(ea):
                yield ea
            continue
        return
