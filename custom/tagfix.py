import six, sys, logging
import functools,operator,itertools,types

import database as db, function as func, ui
import internal

import idaapi
output = sys.stderr

def fetch_contents(f):
    addr,tags = {},{}

    for ea in func.iterate(f):
        ui.navigation.auto(ea)
        res = db.tag(ea)
        #res.pop('name', None)
        for k, v in six.iteritems(res):
            addr[ea] = addr.get(ea,0) + 1
            tags[k] = tags.get(k,0) + 1
        continue
    return func.top(f), addr, tags

def check_contents(ea):
    node, key = internal.netnode.get(internal.comment.tagging.node()), internal.comment.contents._key(ea)
    tag = internal.comment.decode(db.get_comment(key))

    encdata = internal.netnode.sup.get(node, key)
    if encdata is None and tag: return False
    if not isinstance(tag, dict): return False
    if not tag: return True
    if '__address__' not in tag: return False
    if '__tags__' not in tag: return False
    return True

def check_global(ea):
    if func.within(ea): return False

    cache = internal.comment.decode(db.get_comment(db.top()))
    cache.update( internal.comment.decode(db.get_comment(db.bottom())) )

    node = internal.netnode.get(internal.comment.tagging.node())
    tag = internal.comment.decode(db.get_comment(ea))

    if cache and '__address__' not in cache: return False
    if not cache and tag: return False
    count = internal.netnode.alt.get(node, ea)
    if tag and not count: return False

    if len(tag['__address__']) != count: return False
    keys = tag['__tags__']
    if any(t not in cache for t in keys): return False
    return True

def fetch_globals_functions():
    addr,tags = {},{}
    t = len(list(db.functions()))
    for i, ea in enumerate(db.functions()):
        ui.navigation.auto(ea)
        print >>output, "globals: fetching tag from function {:#x} : {:d} of {:d}".format(ea, i, t)
        res = func.tag(ea)
        #res.pop('name', None)
        for k, v in six.iteritems(res):
            addr[ea] = addr.get(ea, 0) + 1
            tags[k] = tags.get(k, 0) + 1
        continue
    return addr, tags

def fetch_globals_data():
    addr,tags = {},{}
    left, right = db.range()
    print >>output, 'globals: fetching tags from data'
    for ea in db.iterate(left, right):
        if func.within(ea): continue
        ui.navigation.auto(ea)

        res = db.tag(ea)
        #res.pop('name', None)
        for k, v in six.iteritems(res):
            addr[ea] = addr.get(ea, 0) + 1
            tags[k] = tags.get(k, 0) + 1
        continue
    return addr, tags

def fetch_globals():
    # read addr and tags from all functions/globals
    faddr,ftags = fetch_globals_functions()
    daddr,dtags = fetch_globals_data()

    # consolidate tags into individual dictionaries
    print >>output, 'globals: aggregating results'
    addr,tags = dict(faddr), dict(ftags)
    for k, v in six.iteritems(daddr):
        addr[k] = addr.get(k, 0) + v
    for k, v in six.iteritems(dtags):
        tags[k] = tags.get(k, 0) + v

    print >>output, "globals: found {:d} addrs".format(len(addr))
    print >>output, "globals: found {:d} tags".format(len(tags))

    return addr,tags

def contents(ea):
    '''Iterate through all addresses in the function ``ea`` and its tagcache collecting any found tags.'''
    try:
        func.top(ea)
    except LookupError:
        return {}, {}

    # read addresses and tags from contents
    ui.navigation.auto(ea)
    logging.debug("contents<{:#x}>: fetching contents from function".format(ea))
    f, addr, tags = fetch_contents(ea)

    # clean out any hidden tag values
    for k in six.viewkeys(tags):
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

    # update addresses and tags to contents
    ui.navigation.set(ea)
    logging.debug("contents<{:#x}>: updating contents name ref".format(ea))
    for k, v in six.iteritems(tags):
        internal.comment.contents.set_name(f, k, v)

    logging.debug("contents<{:#x}>: updating contents address ref".format(ea))
    for k, v in six.iteritems(addr):
        if not func.within(k):
            continue
        internal.comment.contents.set_address(k, v)

    return addr, tags

def globals():
    '''Iterate through all globals in the database and update the tagcache with any found tags.'''

    # read all function and data tags
    addr, tags = fetch_globals()

    # update the global state
    print >>output, 'globals: updating global name refs'
    for k, v in six.iteritems(tags):
        internal.comment.globals.set_name(k, v)

    print >>output, 'globals: updating global address refs'
    for k, v in six.iteritems(addr):
        internal.comment.globals.set_address(k, v)

    return addr, tags

def all():
    '''Iterate through everything in the database and update the tagcache with any found tags.'''
    total = len(list(db.functions()))

    # process all function contents tags
    for i, ea in enumerate(db.functions()):
        print >>output, "updating references for contents ({:#x}) : {:d} of {:d}".format(ea, i, total)
        _, _ = contents(ea)

    # process all global tags
    print >>output, 'updating references for globals'
    _, _ = globals()

def customnames():
    '''Add all custom names defined in the database to the tagcache as "__name__"'''
    # FIXME: first delete all the custom names '__name__' tag
    left, right = db.range()
    for ea in db.iterate(left, right):
        ctx = internal.comment.globals if not func.within(ea) or func.top(ea) == ea else internal.comment.contents
        if db.type.has_customname(ea):
            ctx.inc(ea, '__name__')
        continue
    return

def extracomments():
    '''Add all extra cmts in the database to the tagcache as "__extra_prefix__" or "__extra_suffix__"'''
    # FIXME: first delete all the custom names '__name__' tag
    left, right = db.range()
    for ea in db.iterate(left, right):
        ctx = internal.comment.contents if func.within(ea) else internal.comment.globals

        count = db.extra.__count__(ea, idaapi.E_PREV)
        if count: [ ctx.inc(ea, '__extra_prefix__') for i in six.moves.range(count) ]

        count = db.extra.__count__(ea, idaapi.E_NEXT)
        if count: [ ctx.inc(ea, '__extra_suffix__') for i in six.moves.range(count) ]
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
    total = sum(map(next, (iter1, iter2)))

    current = 0
    for idx, ea in iter1:
        print >>output, "erasing contents for function {:#x} : {:d} of {:d}".format(ea, idx, total)

    res = idx + 1
    for idx, addressOrName in iter2:
        fmt = "{:#x}" if isinstance(addressOrName, six.integer_types) else "tagname {!r}"
        print >>output, "erasing global {:s} : {:d} of {:d}".format(fmt.format(addressOrName), res+idx, total)
    return

__all__ = ['everything','globals','contents']
