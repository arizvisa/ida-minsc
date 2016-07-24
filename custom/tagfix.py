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
    for ea in db.functions():
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
    print 'doing functions'
    faddr,ftags = do_functions()
    print 'doing database'
    daddr,dtags = do_data()

    print 'aggregating them'
    addr,tags = dict(faddr), dict(ftags)
    for k,v in daddr.items():
        addr[k] = addr.get(k, 0) + v
    for k,v in dtags.items():
        tags[k] = tags.get(k, 0) + v

    print 'found {:d} addrs'.format(len(addr))
    print 'found {:d} tags'.format(len(tags))

    return addr,tags

def function(ea):
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

def database():
    addr, tags = do_globally()
    
    for ea in internal.comment.globals.address():
        internal.comment.globals.set_address(ea, 0)
    for name in internal.comment.globals.name():
        internal.comment.globals.set_name(0)

    print 'doing tags'
    for k,v in tags.items():
        internal.comment.globals.set_name(k, v)

    print 'doing addresses'
    for k,v in addr.items():
        internal.comment.globals.set_address(k, v)

    return addr, tags

def everything():
    total = len(list(db.functions()))
    addr,tags = {}, {}
    for i,ea in enumerate(db.functions()):
        print '{:x} : function content : {:d} of {:d}'.format(ea, i, total)

        for addr in internal.comment.contents.address(ea):
            internal.comment.contents.set_address(addr, 0)
        for name in internal.comment.contents.name(ea):
            internal.comment.contents.set_name(ea, name, 0)

        _, _ = function(ea)
    print 'yay : doing entire database globals and function-level'
    _, _ = database()
