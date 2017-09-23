import database as db, function as fn, structure as st
import sys, itertools, operator, logging

import internal, idaapi

output = sys.stderr

def function(ea):
    '''Yield each tag defined within a function.'''
    for ea in fn.iterate(ea):
        t = db.tag(ea)
        if t: yield ea, t
    return

def frame(ea):
    for member in fn.frame(ea).members:
        if any(member.name.startswith(n) for n in ('arg_', 'var_', ' ')) and not member.comment:
            continue
        if isinstance(member.type, st.structure_t) or any(isinstance(n, st.structure_t) for n in member.type):
            logging.warn("{:s}.frame({:#x}) : Skipping structure-based type for field {:+#x} : {!r}".format(__name__, ea, member.offset, member.type))
            yield member.offset, (member.name, None, member.comment)
            continue
        yield member.offset, (member.name, member.type, member.comment)
    return

def globals():
    '''Yields all the global tags.'''
    ea, sentinel = db.range()
    while ea < sentinel:
        f = idaapi.get_func(ea)
        if f:
            t = fn.tag(ea)
            if t: yield ea, t
            ea = f.endEA
            continue
        t = db.tag(ea)
        if t: yield ea, t
        ea = db.a.next(ea)
    return

def frames():
    '''Yields all the frames for each function within the database.'''
    for ea in db.functions():
        res = dict(frame(ea))
        if res: yield ea, res
    return

def everything(use_cache=False):
    '''Return all the tags within the database as (globals, contents, frames).'''
    if use_cache:
        g, f = cached()

    else:
        print >>output, '--> Grabbing globals...'
        g = {ea : d for ea, d in globals()}

        print >>output, '--> Grabbing contents from all functions...'
        res = (function(ea) for ea in db.functions())
        f = {}
        map(f.update, itertools.imap(dict, itertools.ifilter(None, res)))

    print >>output, '--> Grabbing frames from all functions...'
    h = {ea : d for ea, d in frames()}
    return (g, f, h)

def cached():
    '''Return all tags using the database's tag cache as (globals, contents).'''
    print >>output, '--> Grabbing globals (cached)...'
    g = {ea : t for ea, t in db.select()}

    print >>output, '--> Grabbing contents from all functions (cached)...'
    res = itertools.starmap(fn.select, db.selectcontents())
    f = {ea : t for ea, t in itertools.chain(*res)}

    return (g, f)

def apply_frame(ea, frame, **tagmap):
    F = fn.frame(ea)
    for offset, (name, type, comment) in frame.viewitems():
        try:
            member = F.by_offset(offset)
        except LookupError:
            logging.warn("{:s}.apply_frame({:x}, ...) : Unable to find frame member at {:+#x}. Skipping application of data to it. : {!r}".format(__name__, ea, offset, (name, type, comment)), exc_info=True)
            continue

        if member.name != name:
            if any(not member.name.startswith(n) for n in ('arg_','var_',' ')):
                print >>output, "{:x} : {:+x} : Renaming frame member with new name. : {!r} : {!r}".format(ea, offset, member.name, name)
            member.name = name

        d, state = map(internal.comment.decode, (comment, member.comment))
        for k in d.viewkeys() & state.viewkeys():
            if state[k] == d[k]: continue
            print >>output, "{:x} : {:+x} : Overwriting frame member tag with new value. : {!r} : {!r}".format(ea, offset, state[k], d[k])
        mapstate = { tagmap.get(k, k) : v for k, v in d.iteritems() }
        state.update(mapstate)
        member.comment = internal.comment.encode(state)

        if type is not None:
            member.type = type
        continue
    return

def load((g, f, h), **tagmap):
    '''Write all the tags from (g, f, h) into the database.'''
    first = operator.itemgetter(0)

    print >>output, "--> Writing globals... ({:d} entr{:s})".format(len(g), 'y' if len(g) == 1 else 'ies')
    for ea, d in sorted(g.items(), key=first):
        m = fn if fn.within(ea) else db

        state = m.tag(ea)
        for k in state.viewkeys() & d.viewkeys():
            if state[k] == d[k]: continue
            print >>output, "{:x} : {!r} : Overwriting global tag with new value. : {!r} : {!r}".format(ea, k, state[k], d[k])

        try:
            [ m.tag(ea, tagmap.get(k, k), v) for k, v in d.iteritems() ]
        except:
            logging.warn("{:s}.load : {:x} : Unable to apply tags to global. : {!r}".format(__name__, ea, d), exc_info=True)
        continue

    print >>output, "--> Writing function contents... ({:d} entr{:s})".format(len(f), 'y' if len(f) == 1 else 'ies')
    for ea, d in sorted(f.items(), key=first):
        state = db.tag(ea)
        for k in state.viewkeys() & d.viewkeys():
            if state[k] == d[k]: continue
            print >>output, "{:x} : {!r} : Overwriting contents tag with new value. : {!r} : {!r}".format(ea, k, state[k], d[k])

        try:
            [ db.tag(ea, tagmap.get(k, k), v) for k, v in d.iteritems() ]
        except:
            logging.warn("{:s}.load : {:x} : Unable to apply tags to contents. : {!r}".format(__name__, ea, d), exc_info=True)
        continue

    print >>output, "--> Applying frames to each function... ({:d} entr{:s})".format(len(h), 'y' if len(h) == 1 else 'ies')
    for ea, d in sorted(h.items(), key=first):
        try:
            apply_frame(ea, d)
        except:
            logging.warn("{:s}.load : {:x} : Unable to apply tags to frame. : {!r}".format(__name__, ea, d), exc_info=True)
        continue
    return

def export(*tags, **boolean):
    '''Return the selected tags within the database as (globals, contents, {}).'''
    def globals(*tags, **boolean):
        for ea, res in db.select(*tags, **boolean):
            yield ea, res
        return

    def contents(*tags, **boolean):
        for res in db.selectcontents(*tags, **boolean):
            for ea, res in fn.select(*res):
                yield ea, res
            continue
        return

    print >>output, '--> Grabbing globals...'
    g = {ea : d for ea, d in globals(*tags, **boolean)}
    print >>output, '--> Grabbing contents from functions...'
    f = {ea : d for ea, d in contents(*tags, **boolean)}
    return g, f, {}

def list():
    '''Return all the contents tags within the database as a set.'''
    return {t for t in itertools.chain(*(t for _, t in db.selectcontents()))}
