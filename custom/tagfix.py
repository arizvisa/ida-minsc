import database as db,function as fn
import internal
import itertools,functools,operator
import idaapi

def fetch_function(f):
    addr,tags = {},{}
    
    for ea in fn.iterate(f):
        res = db.tag(ea)
        res.pop('name', None)
        for k,v in res.items():
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
        for k,v in res.items():
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
        for k,v in res.items():
            addr[ea] = addr.get(ea, 0) + 1
            tags[k] = tags.get(k, 0) + 1
        continue
    return addr, tags

def do_globally():
    faddr,ftags = do_functions()
    daddr,dtags = do_data()

    print 'aggregating results'
    addr,tags = dict(faddr), dict(ftags)
    for k,v in daddr.items():
        addr[k] = addr.get(k, 0) + v
    for k,v in dtags.items():
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

    for k,v in tags.items():
        internal.comment.contents.set_name(f, k, v)

    for k,v in addr.items():
        if not fn.within(k):
            continue
        internal.comment.contents.set_address(k, v)

    return addr, tags

def globals():
    '''Iterate through all globals in the database and update the tagcache with any found tags.'''
    addr, tags = do_globally()
    
    print 'initializing global references as empty'
    for ea in internal.comment.globals.address():
        internal.comment.globals.set_address(ea, 0)
    for name in internal.comment.globals.name():
        internal.comment.globals.set_name(0)

    print 'updating global name refs'
    for k,v in tags.items():
        internal.comment.globals.set_name(k, v)

    print 'updating global address refs'
    for k,v in addr.items():
        internal.comment.globals.set_address(k, v)

    return addr, tags

def all():
    '''Iterate through everything in the database and update the tagcache with any found tags.'''
    total = len(list(db.functions()))
    addr,tags = {}, {}
    for i,ea in enumerate(db.functions()):

        for addr in internal.comment.contents.address(ea):
            internal.comment.contents.set_address(addr, 0)
        for name in internal.comment.contents.name(ea):
            internal.comment.contents.set_name(ea, name, 0)

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
    print 'erasing database globals'
    erase_globals()
    t = len(list(db.functions()))
    for i, ea in enumerate(db.functions()):
        print '{:x} : erasing contents for function {:d} of {:d}'.format(ea, i, t)
        erase_contents(ea)
    all()

def erase_contents(ea):
    ea = fn.top(ea)
    n = internal.comment.contents.node()
    for addr in internal.netnode.sup.fiter(n):
        internal.netnode.sup.remove(n, addr)
    for key in internal.netnode.hash.fiter(n):
        internal.netnode.hash.remove(n, key)

    # old blob-based
    res = internal.netnode.blob.get(ea, idaapi.stag)
    if res and res.startswith('BZh9'):
        internal.netnode.blob.remove(ea, idaapi.stag)

    # new blob-blased
    res = internal.netnode.blob.get(ea, internal.comment.contents.btag)
    if res and res.startswith('BZh9'):
        internal.netnode.blob.remove(ea, internal.comment.contents.btag)
    return

def erase_globals():
    internal.netnode.remove( internal.comment.globals.node() )
    l, r = db.range()
    for ea in db.iterate(l, r-1):
        if idaapi.get_func(ea): continue

        # old blob-based
        res = internal.netnode.blob.get(ea, idaapi.stag)
        if res and res.startswith('BZh9'):
            internal.netnode.blob.remove(ea, idaapi.stag)

        # new blob-based
        res = internal.netnode.blob.get(ea, internal.comment.contents.btag)
        if res and res.startswith('BZh9'):
            internal.netnode.blob.remove(ea, internal.comment.contents.btag)
        continue
    return

__all__ = ['everything','globals','function']
