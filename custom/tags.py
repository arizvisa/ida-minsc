import six, sys, logging
import functools,operator,itertools,types

import database as db, function as func, structure as struc, ui
import internal

output = sys.stderr

def function(ea):
    '''Yield each tag defined within a function.'''
    for ea in func.iterate(ea):
        ui.navigation.set(ea)
        t = db.tag(ea)
        if t: yield ea, t
    return

def frame(ea):
    for member in func.frame(ea).members:
        if any(member.name.startswith(n) for n in ('arg_', 'var_', ' ')) and not member.comment:
            continue
        if isinstance(member.type, struc.structure_t) or any(isinstance(n, struc.structure_t) for n in member.type):
            logging.info("{:s}.frame({:#x}) : Storing structure-based type as name for field {:+#x} : {!r}".format(__name__, ea, member.offset, member.type))
            yield member.offset, (member.name, member.type.name, member.comment)
            continue
        yield member.offset, (member.name, member.type, member.comment)
    return

def globals():
    '''Yields all the global tags.'''
    ea, sentinel = db.config.bounds()
    while ea < sentinel:
        ui.navigation.auto(ea)
        if func.within(ea):
            t = func.tag(ea)
            if t: yield ea, t
            _, ea = func.chunk(ea)
            continue
        t = db.tag(ea)
        if t: yield ea, t
        try: ea = db.a.next(ea)
        except StandardError: ea = sentinel
    return

def frames():
    '''Yields all the frames for each function within the database.'''
    for ea in db.functions():
        ui.navigation.procedure(ea)
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
    res = itertools.starmap(func.select, db.selectcontents())
    f = {ea : t for ea, t in itertools.chain(*res)}

    return (g, f)

def apply_frame(ea, frame, **tagmap):
    F = func.frame(ea)
    for offset, (name, type, comment) in frame.viewitems():
        try:
            member = F.by_offset(offset)
        except LookupError:
            logging.warn("{:s}.apply_frame({:x}, ...) : Unable to find frame member at {:+#x}. Skipping application of data to it. : {!r}".format(__name__, ea, offset, (name, type, comment)))
            continue

        if member.name != name:
            if any(not member.name.startswith(n) for n in ('arg_','var_',' ')):
                print >>output, "{:x} : {:+x} : Renaming frame member with new name. : {!r} : {!r}".format(ea, offset, member.name, name)
            member.name = name

        d, state = map(internal.comment.decode, (comment, member.comment))
        for k in d.viewkeys() & state.viewkeys():
            if state[k] == d[k]: continue
            print >>output, "{:x} : {:+x} : Overwriting frame member tag with new value. : {!r} : {!r}".format(ea, offset, state[k], d[k])
        mapstate = { tagmap.get(k, k) : v for k, v in six.iteritems(d) }
        state.update(mapstate)
        member.comment = internal.comment.encode(state)

        if isinstance(type, basestring):
            try:
                member.type = struc.by(type)
            except LookupError:
                logging.warn("{:s}.apply_frame({:x}, ...): Unable to find structure {!r} for member at {:+#x}. Skipping. it.".format(__name__, ea, type, offset))
        else:
            member.type = type
        continue
    return

def load((g, f, h), **tagmap):
    '''Write all the tags from (g, f, h) into the database.'''
    first = operator.itemgetter(0)

    print >>output, "--> Writing globals... ({:d} entr{:s})".format(len(g), 'y' if len(g) == 1 else 'ies')
    for ea, d in sorted(g.items(), key=first):
        m = fn if func.within(ea) else db

        state = m.tag(ea)
        for k in state.viewkeys() & d.viewkeys():
            if state[k] == d[k]: continue
            print >>output, "{:x} : {!r} : Overwriting global tag with new value. : {!r} : {!r}".format(ea, k, state[k], d[k])

        try:
            [ m.tag(ea, tagmap.get(k, k), v) for k, v in six.iteritems(d) ]
        except:
            logging.warn("{:s}.load : {:x} : Unable to apply tags to global. : {!r}".format(__name__, ea, d))
        continue

    print >>output, "--> Writing function contents... ({:d} entr{:s})".format(len(f), 'y' if len(f) == 1 else 'ies')
    for ea, d in sorted(f.items(), key=first):
        state = db.tag(ea)
        for k in state.viewkeys() & d.viewkeys():
            if state[k] == d[k]: continue
            print >>output, "{:x} : {!r} : Overwriting contents tag with new value. : {!r} : {!r}".format(ea, k, state[k], d[k])

        try:
            [ db.tag(ea, tagmap.get(k, k), v) for k, v in six.iteritems(d) ]
        except:
            logging.warn("{:s}.load : {:x} : Unable to apply tags to contents. : {!r}".format(__name__, ea, d))
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
            for ea, res in func.select(*res):
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
