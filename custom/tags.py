import database as db,function as fn
import itertools

import idaapi

def function(ea):
    res = {}
    for ea in fn.iterate(ea):
        t = db.tag(ea)
        if t: res[ea] = t
    return res

def globals():
    '''Return all the global tags.'''
    res = {}
    ea, sentinel = db.range()
    while ea < sentinel:
        f = idaapi.get_func(ea)
        if f:
            ea = f.endEA
            continue
        t = db.tag(ea)
        if t: res[ea] = t
        ea = db.a.next(ea)
    return res

def everything():
    '''Return all the tags within the database as (globals,contents).'''
    print 'Grabbing globals...'
    g = globals()

    print 'Grabbing contents from all functions...'
    res = (function(ea) for ea in db.functions())
    f = {}
    map(f.update, (d for d in res if d))

    return (g,f)

def cached():
    '''Return all tags using the database's tag cache as (globals,contents).'''
    print 'Grabbing globals...'
    g = {ea : t for ea,t in db.select()}

    print 'Grabbing contents from all functions...'
    res = itertools.starmap(fn.select, db.selectcontents())
    f = {ea:t for ea,t in itertools.chain(*res)}

    return (g,f)

def load((g,f)):
    '''Write all the tags from (g,f) into the database.'''
    print 'Writing globals...'
    for ea,d in g.iteritems():
        for k,v in d.iteritems():
            fn.tag(ea, k, v)
        continue

    print 'Writing function contents...'
    for ea, d in f.iteritems():
        for k,v in d.iteritems():
            db.tag(ea, k, v)
        continue
    return

