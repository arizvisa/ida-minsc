import __builtin__
import sys,logging
import database,function,instruction as ins
import internal

class remote(object):
    '''For poor folk without a dbgeng'''
    def __init__(self, remotebaseaddress, localbaseaddress=None):
        if localbaseaddress is None:
            localbaseaddress = database.baseaddress()
        self.lbase = localbaseaddress
        self.rbase = remotebaseaddress

    def get(self, addr):
        offset = addr - self.rbase
        return offset + self.lbase

    def put(self, ea):
        offset = ea - self.lbase
        return offset + self.rbase

    def go(self, ea):
        database.go( self.get(ea) )

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
        try: f.add(function.top(ea))
        except (LookupError,ValueError): pass

    # tag the functions too
    for ea in list(f):
        m = function.marks(ea)
        function.tag(ea, 'marks', [ea for ea,_ in m])
    return

def recovermarks():
    '''Utilizing any tag information found in the database, recreate all the database marks.'''
    # collect
    result = []
    for fn,l in database.select('marks'):
        m = set( (l['marks']) if hasattr(l['marks'],'__iter__') else [int(x,16) for x in l['marks'].split(',')] if type(l['marks']) is str else [l['marks']])
        res = [(ea,d['mark']) for ea,d in function.select(fn,'mark')]
        if m != set(a for a,_ in res):
            logging.warning("{:x}: ignoring cached version of marks due to being out-of-sync with real values : {!r} : {!r}".format(fn, __builtin__.map(hex,m), __builtin__.map(hex,set(a for a,_ in res))))
        result.extend(res)
    result.sort(cmp=lambda x,y: cmp(x[1],y[1]))

    # discovered marks versus database marks
    result = dict(result)
    current = {ea:descr for ea,descr in database.marks()}

    # create tags
    for x,y in result.items():
        if x in current:
            logging.warning("{:x}: skipping already existing mark : {!r}".format(x, current[x]))
            continue

        # x not in current
        if x not in current:
            logging.info("{:x}: adding missing mark due to tag : {!r}".format(x, result[x]))
        elif current[x] != result[x]:
            logging.info("{:x}: database tag is different than mark description : {!r}".format(x, result[x]))
        else:
            assert current[x] == result[x]
        database.mark(x, y)

    # marks that aren't reachable in the database
    for ea in set(current.viewkeys()).difference(result.viewkeys()):
        logging.warning("{:x}: unreachable mark (global) : {!r}".format(ea, current[ea]))

    # color them
    colormarks()

def checkmarks():
    '''Output all functions (sys.stdout) containing more than 1 mark.'''
    res = []
    for a,m in database.marks():
        try:
            res.append((function.top(a), a, m))
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
        print >>sys.stdout, "{:x} : in function {:s}".format(k,function.name(function.byAddress(k)))
        print >>sys.stdout, '\n'.join( ("- {:x} : {:s}".format(a,m) for a,m in sorted(v)) )
    return

def collect(ea, sentinel):
    '''Collect all the basic-blocks starting at address ``ea`` and terminating when an address in the set ``sentinel`` is reached.'''
    if isinstance(sentinel, list):
        sentinel = set(sentinel)
    if not all((sentinel, isinstance(sentinel, set))):
        raise AssertionError("{:s}.collect({:x}, {!r}) : Sentinel is empty or not a set.".format(__name__, ea, sentinel))
    def _collect(addr, result):
        process = set()
        for blk in __builtin__.map(function.block, function.block.after(addr)):
            if any(blk in coll for coll in (result,sentinel)):
                continue
            process.add(blk)
        for addr, _ in process:
            result |= _collect(addr, result | process)
        return result
    addr, _ = blk = function.block(ea)
    return _collect(addr, set([blk]))

def above(ea, includeSegment=False):
    '''Display all the callers of the function at /ea/'''
    tryhard = lambda ea: "{:s}+{:x}".format(function.name(function.top(ea)),ea-function.top(ea)) if function.within(ea) else "+{:x}".format(ea) if function.name(ea) is None else function.name(ea)
    return '\n'.join(':'.join((segment.name(ea),tryhard(ea)) if includeSegment else (tryhard(ea),)) for ea in function.up(ea))

def below(ea, includeSegment=False):
    '''Display all the functions that the function at /ea/ can call'''
    tryhard = lambda ea: "{:s}+{:x}".format(function.name(function.top(ea)),ea-function.top(ea)) if function.within(ea) else "+{:x}".format(ea) if function.name(ea) is None else function.name(ea)
    return '\n'.join(':'.join((segment.name(ea),tryhard(ea)) if includeSegment else (tryhard(ea),)) for ea in function.down(ea))

# FIXME: this only works on x86 where args are pushed via stack
def makecall(ea=None, target=None):
    """Output the function call at ``ea`` and its arguments in C-form.
    If ``target`` is specified, then assume that the instruction is calling ``target``.
    """
    ea = current.address() if ea is None else ea
    if not function.contains(ea, ea):
        return None

    if database.config.bits() != 32:
        raise RuntimeError("{:s}.makecall({!r},{!r}) : Unable to determine arguments for {:s} due to {:d}-bit calling convention.".format(__name__, ea, target, database.disasm(ea), database.config.bits()))

    if target is None:
        # scan down until we find a call that references something
        chunk, = ((l,r) for l,r in function.chunks(ea) if l <= ea <= r)
        result = []
        while (len(result) < 1) and ea < chunk[1]:
            # FIXME: it's probably not good to just scan for a call
            if not database.instruction(ea).startswith('call '):
                ea = database.next(ea)
                continue
            result = database.cxdown(ea)
            if len(result) == 0: raise TypeError("{:s}.makecall({!r},{!r}) : Unable to determine number of arguments".format(__name__, ea, target))

        if len(result) != 1:
            raise ValueError("{:s}.makecall({!r},{!r}) : Too many targets for call at {:x} : {!r}".format(__name__, ea, result))
        fn, = result
    else:
        fn = target

    try:
        result = []
        for offset,name,size in function.arguments(fn):
            left = database.address.prevstack(ea, offset+database.config.bits()/8)
            # FIXME: if left is not an assignment or a push, find last assignment
            result.append((name,left))
    except LookupError:
        raise LookupError("{:s}.makecall({!r},{!r}) : Unable to get arguments for target function".format(__name__, ea, target))

    # FIXME: replace these crazy list comprehensions with something more comprehensible.
#    result = ["{:s}={:s}".format(name,ins.op_repr(ea, 0)) for name,ea in result]
    result = ["({:x}){:s}={:s}".format(ea, name, ':'.join(ins.op_repr(database.address.prevreg(ea, ins.op_value(ea,0), write=1), n) for n in ins.ops_read(database.address.prevreg(ea, ins.op_value(ea,0), write=1))) if ins.op_type(ea,0) == 'reg' else ins.op_repr(ea, 0)) for name,ea in result]

    try:
        return "{:s}({:s})".format(internal.declaration.demangle(function.name(function.by_address(fn))), ','.join(result))
    except:
        pass
    return "{:s}({:s})".format(internal.declaration.demangle(database.name(fn)), ','.join(result))

def source(ea, *regs):
    '''Return the addresses and which specific operands write to the specified regs'''
    res = []
    for r in regs:
        pea = database.address.prevreg(ea, r, write=1)
        res.append( (pea,tuple(ins.ops_read(pea))) )
    return res

def sourcechain(fn, *args, **kwds):
#    sentinel = kwds.get('types', set(('imm','phrase','addr','void')))
    sentinel = kwds.get('types', set(('imm','addr','void')))

    # XXX: was this supposed to be a linked list of relationships
    #      to the top of a function?
    result = {}
    for ea,opi in source(*args):
        if not function.contains(fn, ea): continue
        opt = tuple(ins.op_type(ea,i) for i in opi)
        for i,t in zip(opi,opt):
            if t in sentinel:
                result.setdefault(ea,set()).add(i)
            elif t in ('reg',):
                result.setdefault(ea,set()).add(i)
                r = ins.op_value(ea,i)
                for a,b in sourcechain(fn, ea, r):
                    __builtin__.map(result.setdefault(a,set()).add, b)
            elif t in ('phrase',):
                result.setdefault(ea,set()).add(i)
                _,(r1,r2,_) = ins.op_value(ea,i)
                for a,b in sourcechain(fn, ea, *tuple(r for r in (r1,r2) if r is not None)):
                    __builtin__.map(result.setdefault(a,set()).add, b)
            elif t in ('imm','addr',):
                result.setdefault(ea,set()).add(i)
            else:
                raise ValueError, (t, ea, i)
            continue
        continue
    return [(ea,result[ea]) for ea in sorted(result.keys())]

def map(l, *args, **kwds):
    """Execute provided callback on all functions in database. Synonymous to map(l,db.functions()).
    ``l`` is defined as a function(address, *args, **kwds).
    Any other arguments are passed to ``l`` unmodified.
    """
    i, x = 0, database.here()
    current = x
    all = database.functions()
    result = []
    try:
        for i,x in enumerate(all):
            database.go(x)
            print("{:x}: processing # {:d} of {:d} : {:s}".format(x, i+1, len(all), function.name(x)))
            result.append( l(x, *args, **kwds) )
    except KeyboardInterrupt:
        print("{:x}: terminated at # {:d} of {:d} : {:s}".format(x, i+1, len(all), function.name(x)))
    database.go(current)
    return result

