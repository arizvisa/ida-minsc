import database as db,function as fn
import internal
import itertools,functools,operator
import idaapi

def fetch_function(f):
    addr,tags = {},{}
    
    for ea in fn.iterate(f):
        res = db.tag(ea)
        res.pop('name', None)
        for k, v in res.iteritems():
            addr[ea] = addr.get(ea,0) + 1
            tags[k] = tags.get(k,0) + 1
        continue
    ea = f
    return fn.top(ea), addr, tags

def check_function(ea):
    node, key = internal.netnode.get(internal.comment.contents.Node), internal.comment.contents._key(ea)
    tag = internal.comment.decode(db.get_comment(key))

    encdata = internal.netnode.sup.get(node, key)
    if encdata is None and tag: return False
    if not isinstance(tag, dict): return False
    if not tag: return True
    if '__address__' not in tag: return False
    if '__tags__' not in tag: return False
    return True

def check_global(ea):
    if idaapi.get_func(ea): return False

    cache = internal.comment.decode(db.get_comment(db.top()))
    cache.update( internal.comment.decode(db.get_comment(db.bottom())) )

    node = internal.netnode.get(internal.comment.globals.Node)
    tag = internal.comment.decode(db.get_comment(ea))

    if cache and '__address__' not in cache: return False
    if not cache and tag: return False
    count = internal.netnode.alt.get(node, ea)
    if tag and not count: return False

    if len(tag['__address__']) != count: return False
    keys = tag['__tags__']
    if any(t not in cache for t in keys): return False
    return True

def do_functions():
    addr,tags = {},{}
    t = len(list(db.functions()))
    for i, ea in enumerate(db.functions()):
        print '{:x} : fetching function {:d} of {:d}'.format(ea, i, t)
        res = fn.tag(ea)
        res.pop('name', None)
        for k, v in res.iteritems():
            addr[ea] = addr.get(ea, 0) + 1
            tags[k] = tags.get(k, 0) + 1
        continue
    return addr, tags

def do_data():
    addr,tags = {},{}
    left, right = db.range()
    print 'fetching global tags'
    for ea in db.iterate(left, right-1):
        f = idaapi.get_func(ea)
        if f is not None: continue
        res = db.tag(ea)
        res.pop('name', None)
        for k, v in res.iteritems():
            addr[ea] = addr.get(ea, 0) + 1
            tags[k] = tags.get(k, 0) + 1
        continue
    return addr, tags

def do_globally():
    faddr,ftags = do_functions()
    daddr,dtags = do_data()

    print 'aggregating results'
    addr,tags = dict(faddr), dict(ftags)
    for k, v in daddr.iteritems():
        addr[k] = addr.get(k, 0) + v
    for k, v in dtags.iteritems():
        tags[k] = tags.get(k, 0) + v

    print 'found {:d} addrs'.format(len(addr))
    print 'found {:d} tags'.format(len(tags))

    return addr,tags

def function(ea):
    '''Iterate through all addresses in the function ``ea`` and it's tagcache with any found tags.'''
    try:
        fn.top(ea)
    except LookupError:
        return {},{}
    f, addr, tags = fetch_function(ea)
    
    for k in set(tags.keys()):
        if k in ('__tags__','__address__'):
            if f in addr:
                addr[f] -= 1
                if addr[f] == 0:
                    addr.pop(f)
            if k in tags:
                tags[k] -= 1
                if tags[k] == 0:
                    tags.pop(k)
        continue

    for k, v in tags.iteritems():
        internal.comment.contents.set_name(f, k, v)

    for k, v in addr.iteritems():
        if not fn.within(k):
            continue
        internal.comment.contents.set_address(k, v)

    return addr, tags

def globals():
    '''Iterate through all globals in the database and update the tagcache with any found tags.'''
    addr, tags = do_globally()
    
    print 'updating global name refs'
    for k, v in tags.iteritems():
        internal.comment.globals.set_name(k, v)

    print 'updating global address refs'
    for k, v in addr.iteritems():
        internal.comment.globals.set_address(k, v)

    return addr, tags

def all():
    '''Iterate through everything in the database and update the tagcache with any found tags.'''
    total = len(list(db.functions()))
    addr,tags = {}, {}
    for i, ea in enumerate(db.functions()):
        print '{:x} : updating references for contents : {:d} of {:d}'.format(ea, i, total)
        _, _ = function(ea)
    print 'updating references for globals'
    _, _ = globals()

def customnames():
    '''Add all custom names defined in the database to the tagcache as "__name__"'''
    # FIXME: first delete all the custom names '__name__' tag
    left, right = db.range()
    for ea in db.iterate(left, right-1):
        fn = idaapi.get_func(ea)
        ctx = internal.comment.globals if not fn or fn.startEA == ea else internal.comment.contents
        if db.type.has_customname(ea):
            ctx.inc(ea, '__name__')
        continue
    return

def extracomments():
    '''Add all extra cmts in the database to the tagcache as "__name__"'''
    # FIXME: first delete all the custom names '__name__' tag
    left, right = db.range()
    for ea in db.iterate(left, right-1):
        fn = idaapi.get_func(ea)
        ctx = internal.comment.contents if fn else internal.comment.globals

        count = db.extra.count(ea, idaapi.E_PREV)
        if count: [ ctx.inc(ea, '__extra_prefix__') for i in xrange(count) ]

        count = db.extra.count(ea, idaapi.E_NEXT)
        if count: [ ctx.inc(ea, '__extra_suffix__') for i in xrange(count) ]
    return

def everything():
    '''Re-create the tag cache for all found tags and custom names within the database.'''
    erase()
    all()

def erase_globals():
    n = internal.comment.tagging.node()
    res = internal.netnode.hash.fiter(n), internal.netnode.alt.fiter(n), internal.netnode.sup.fiter(n)
    res = map(list,res)
    total = sum(map(len, res))
    hashes, alts, sups = res

    yield total

    current = 0
    for idx, k in enumerate(hashes):
        internal.netnode.hash.remove(n, k)
        yield current + idx, k

    current += len(hashes)
    for idx, ea in enumerate(sups):
        internal.netnode.sup.remove(n, ea)
        yield current + idx, ea

    current += len(sups)
    for idx, (ea,_) in enumerate(alts):
        internal.netnode.alt.remove(n, ea)
        yield current + idx, ea
    return

def erase_contents():
    res = db.functions()
    total, tag = len(res), internal.comment.contents.btag
    yield total

    for idx, ea in enumerate(db.functions()):
        internal.netnode.blob.remove(ea, tag)
        yield idx, ea
    return

def erase():
    iter1, iter2 = erase_contents(), erase_globals()
    t1, t2 = map(next, (iter1,iter2))
    total = sum((t1,t2))

    current = 0
    for idx, ea in iter1:
        print 'erasing contents for function {:x} : {:d} of {:d}'.format(ea, idx, total)

    for idx, res in iter2:
        print 'erasing global {!r} : {:d} of {:d}'.format(res, t1+idx, total)
    return

__all__ = ['everything','globals','function']
