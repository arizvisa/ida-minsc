import sys,logging
import database,function,instruction as ins

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
            logging.warning("{:x}: ignoring cached version of marks due to being out-of-sync with real values : {!r} : {!r}".format(fn, map(hex,m), map(hex,set(a for a,_ in res))))
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
    if isinstance(sentinel, list):
        sentinel = set(sentinel)
    if not all((sentinel, isinstance(sentinel, set))):
        raise AssertionError("{:s}.collect({:x}, {!r}) : Sentinel is empty or not a set.".format(__name__, ea, sentinel))
    def _collect(addr, result):
        process = set()
        for blk in map(function.block, function.block.after(addr)):
            if any(blk in coll for coll in (result,sentinel)):
                continue
            process.add(blk)
        for addr, _ in process:
            result |= _collect(addr, result | process)
        return result
    addr, _ = blk = function.block(ea)
    return _collect(addr, set([blk]))
