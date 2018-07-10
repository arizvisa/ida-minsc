import six, sys, logging
import functools,operator,itertools,types,string

import database as db, function as func, structure as struc, ui
import internal

output = sys.stderr

### Utility functions and classes
def lvarNameQ(name):
    '''Determine whether a name is something that IDA named automatically.'''
    if any(name.startswith(n) for n in ('arg_', 'var_')):
        res = name.split('_', 2)[-1]
        return all(n in string.hexdigits for n in res)
    elif name.startswith(' '):
        return name[1:] in {'s', 'r'}
    return False

class dummy(object):
    def __eq__(self, other): return False
    def __cmp__(self, other): return -1
dummy = dummy()

### Reading tags from individual components within database
def __function_uncached(ea):
    '''Yield each tag defined within a function by walking it.'''
    F = func.by(ea)

    ## iterate through every address in the function
    for ea in func.iterate(F):
        ui.navigation.set(ea)

        ## yield the tags
        res = db.tag(ea)
        yield ea, res
    return

def __function_cached(ea):
    '''Yield each tag defined within a function using the tag cache.'''
    F = func.by(ea)

    ## iterate through every tag in the function's tagcache
    for ea, res in func.select(F):
        ui.navigation.set(ea)

        ## yield the tags
        yield ea, res
    return

def function(ea, use_cache=False):
    """Yields all the tags within the given function.
    If the flag ``use_cache`` is specified, then read tags using the tagcache.
    """
    f = __function_cached if use_cache else __function_uncached
    iterable = f(ea)
    return itertools.ifilter(None, iterable)

def __globals_cached():
    '''Yields all the globally defined tags using the tagcache.'''
    for ea, res in db.select():
        ui.navigation.auto(ea)

        ## yield any tags that were found
        yield ea, res
    return

def __globals_uncached():
    '''Yields all the global tags.'''
    ea, sentinel = db.config.bounds()

    ## loop till we hit the end of the database
    while ea < sentinel:
        ui.navigation.auto(ea)
        funcQ = func.within(ea)

        ## figure out which tag function to use
        f = func.tag if funcQ else db.tag

        ## grab the tag and yield it
        res = f(ea)
        yield res

        ## if we're in a function, then seek to the next chunk
        if funcQ:
            _, ea = func.chunk(ea)
            continue

        ## otherwise, try the next address till we hit a sentinel value
        try: ea = db.a.next(ea)
        except StandardError: ea = sentinel
    return

def globals(use_cache=False):
    """
    Yields all the globally defined tags.
    If the flag ``use_cache`` is True, then read from the tag cache.
    """
    f = __globals_cached if cached else __globals_uncached
    iterable = f()
    return itertools.ifilter(None, iterable)

def frame(ea):
    '''Yield each field within the frame belonging to the function ``ea``'''
    F = func.by(ea)

    ## iterate through all of the frame's members
    res = func.frame(F)
    for member in res.members:
        ## if ida has named it and there's no comment, then skip
        if lvarNameQ(member.name) and not member.comment:
            continue

        ## if it's a structure, then the type is the structure name
        if isinstance(member.type, struc.structure_t):
            logging.info("{:s}.frame({:#x}) : Storing structure-based type as name for field {:+#x} : {!r}".format(__name__, ea, member.offset, member.type))
            type = member.type.name

        ## otherwise, the type is a tuple that we can serializer
        else:
            type = member.type

        ## otherwise, it's just a regular field. so we can just save what's important.
        yield member.offset, (member.name, type, member.comment)
    return

### reading different types of tags from entire database
def frames():
    '''Yields all the frames for each function within the database.'''
    for ea in db.functions():
        ui.navigation.procedure(ea)

        ## grab the frame
        res = dict(frame(ea))

        ## if something is there, then yield it
        if res: yield ea, res
    return

def functions(use_cache=False, use_offset=False):
    """Yields all the function contents for each function within the database.
    If ``use_cache`` is specified, then just read it from the tagcache.
    If ``use_offset`` is specified, then yield the (FunctionEA, ChunkId, Offset) as the key.
    """
    everything = (ea for ea, _ in db.selectcontents()) if use_cache else iter(db.functions())

    ## Iterate through each function in the database
    for ea in everything:
        F = func.by(ea)
        chunks = [ch for ch in func.chunks(F)]

        ## Iterate through the function's contents looking for tags
        for ea, res in function(ea, use_cache=use_cache):

            ## if offset was set to True, then set the location to the tuple (Function, ChunkId, ChunkOffset)
            if use_offset:
                cid, base = next((i, l) for i, (l, r) in enumerate(chunks) if l <= ea < r)
                location = func.top(F), cid, ea - base

            ## otherwise, using just the address is fine
            else:
                location = ea

            ## yield it
            yield location, res
        continue
    return

def cached(use_offset=False):
    '''Return all tags using the database's tag cache as (globals, contents).'''

    ## grab all globals that're cached
    print >>output, '--> Grabbing globals (cached)...'
    g = dict(globals(use_cache=True))

    ## grab any contents that're cached
    print >>output, '--> Grabbing contents from all functions (cached)...'
    c = dict(functions(use_cache=True, use_offset=use_offset))

    return g, c

def uncached(use_offset=False):
    '''Return all tags within the database as (globals, contents).'''

    print >>output, '--> Grabbing globals...'
    g = dict(globals(use_cache=False))

    print >>output, '--> Grabbing contents from all functions...'
    res = dict(functions(use_cache=False, use_offset=use_offset))

    return g, c

def read(use_cache=False, use_offset=False):
    '''Return all the tags within the database as (globals, contents, frames).'''
    f = cached if use_cache else uncached
    Globals, Contents = f(use_offset=use_offset)

    print >>output, '--> Grabbing frames from all functions...'
    Frames = {ea : res for ea, res in frames()}

    return Globals, Contents, Frames

### Applying tags to database
def apply_frame(ea, frame, **tagmap):
    F = func.frame(ea)
    tagmap_output = ", {:s}".format(', '.join("{:s}={:s}".format(k, v) for k, v in six.iteritems(tagmap))) if tagmap else ''

    for offset, (name, type, comment) in six.iteritems(frame):
        try:
            member = F.by_offset(offset)
        except LookupError:
            logging.warn("{:s}.apply_frame({:#x}, ...{:s}) : Unable to find frame member at {:+#x}. Skipping application of data to it. : {!r}".format(__name__, ea, tagmap_output, offset, (name, type, comment)))
            continue

        if member.name != name:
            if any(not member.name.startswith(n) for n in ('arg_','var_',' ')):
                logging.warn("{:s}.apply_frame({:#x}, ...{:s}) : Renaming frame member {:+#x} with new name. : {!r} -> {!r}".format(__name__, ea, tagmap_output, offset, member.name, name))
            member.name = name

        ## check what's going to be overwritten with different values prior to doing it
        state, res = map(internal.comment.decode, (member.comment, comment))

        ## transform the new tag state using the tagmap
        new = { tagmap.get(name, name) : value for name, value in six.viewitems(res) }

        ## check if the tag mapping resulted in the deletion of a tag
        if len(new) != len(res):
            for name in six.viewkeys(res) - six.viewkeys(new):
                logging.warn("{:s}.apply_frame({:#x}, ...{:s}) : Refusing requested tag mapping as it results in tag {!r} overwriting tag {!r} for frame member {:+#x}: {!r} -> {!r}".format(__name__, ea, tagmap_output, tagmap[name], name, offset, res[tagmap[name]], res[name]))
            pass

        ## warn the user about what's going to be overwritten prior to doing it
        for name in six.viewkeys(state) & six.viewkeys(new):
            if state[name] == new[name]: continue
            logging.warn("{:s}.apply_frame({:#x}, ...{:s}) : Overwriting tag {!r} for frame member {:+#x} with new value. : {!r} -> {!r}".format(__name__, ea, tagmap_output, name, offset, state[name], new[name]))

        ## now we can update the current dictionary
        mapstate = { name : value for name, value in six.iteritems(new) if state.get(name, dummy) != value }
        state.update(mapstate)

        ## convert it back to a multi-lined comment and assign it
        member.comment = internal.comment.encode(state)

        ## if the type is a string, then figure out which structure to use
        if isinstance(type, basestring):
            try:
                member.type = struc.by(type)
            except LookupError:
                logging.warn("{:s}.apply_frame({:#x}, ...{:s}): Unable to find structure {!r} for member at {:+#x}. Skipping. it.".format(__name__, ea, tagmap_output, type, offset))

        ## otherwise, it's a pythonic tuple that we can just assign
        else:
            member.type = type
        continue
    return

def apply((globals, contents, frames), **tagmap):
    '''Write all the tags from (globals, contents, frames) into the database.'''
    first = operator.itemgetter(0)
    tagmap_output = ", {:s}".format(', '.join("{:s}={:s}".format(k, v) for k, v in six.iteritems(tagmap))) if tagmap else ''

    print >>output, "--> Writing globals... ({:d} entr{:s})".format(len(globals), 'y' if len(globals) == 1 else 'ies')
    for ea, res in sorted(six.iteritems(globals), key=first):
        ui.navigation.auto(ea)
        ns = func if func.within(ea) else db

        ## grab the current (old) tag state
        state = ns.tag(ea)

        ## transform the new tag state using the tagmap
        new = { tagmap.get(name, name) : value for name, value in six.viewitems(res) }

        ## check if the tag mapping resulted in the deletion of a tag
        if len(new) != len(res):
            for name in six.viewkeys(res) - six.viewkeys(new):
                logging.warn("{:s}.apply(...{:s}) : {:#x} : Refusing requested tag mapping as it results in tag {!r} overwriting tag {!r} for a global tag: {!r} -> {!r}".format(__name__, tagmap_output, ea, tagmap[name], name, res[tagmap[name]], res[name]))
            pass

        ## check what's going to be overwritten with different values prior to doing it
        for name in six.viewkeys(state) & six.viewkeys(new):
            if state[name] == new[name]: continue
            logging.warn("{:s}.apply(...{:s}) : {:#x} : Overwriting global tag {!r} with new value: {!r} -> {!r}".format(__name__, tagmap_output, ea, name, state[name], new[name]))

        ## now we can apply the tags to the global address
        try:
            [ ns.tag(ea, name, value) for name, value in six.iteritems(new) if state.get(name, dummy) != value ]
        except:
            logging.warn("{:s}.apply(...{:s}) : {:#x} : Unable to apply tags to global: {!r}".format(__name__, tagmap_output, ea, new), exc_info=True)
        continue

    print >>output, "--> Writing function contents... ({:d} entr{:s})".format(len(contents), 'y' if len(contents) == 1 else 'ies')
    for loc, res in sorted(six.iteritems(contents), key=first):

        ## if the location is an chunkid and offset, then convert it to an address
        if isinstance(loc, tuple):
            f, cid, ofs = ea
            base, _ = next(b for i, b in enumerate(func.chunks(f)) if i == cid)
            ea = base + ofs

        ## otherwise, it's just an old-fashioned address
        else:
            ea = loc

        ui.navigation.set(ea)

        ## warn the user if this address is not within a function
        if not func.within(ea):
            logging.warn("{:s}.apply(...{:s}) : Address {:#x} is not within a function. Using a global tag.".format(__name__))

        ## grab the current (old) tag state
        state = db.tag(loc)

        ## transform the new tag state using the tagmap
        new = { tagmap.get(name, name) : value for name, value in six.viewitems(res) }

        ## check if the tag mapping resulted in the deletion of a tag
        if len(new) != len(res):
            for name in six.viewkeys(res) - six.viewkeys(new):
                logging.warn("{:s}.apply(...{:s}) : {:#x} : Refusing requested tag mapping as it results in tag {!r} overwriting tag {!r} for a contents tag: {!r} -> {!r}".format(__name__, tagmap_output, ea, tagmap[name], name, res[tagmap[name]], res[name]))
            pass

        ## inform the user if any tags are being overwritten with different values
        for name in six.viewkeys(state) & six.viewkeys(new):
            if state[name] == new[name]: continue
            logging.warn("{:s}.apply(...{:s}) : {:#x} : Overwriting contents tag {!r} with new value: {!r} -> {!r}".format(__name__, tagmap_output, ea, name, state[name], new[name]))

        ## write the tags to the contents address
        try:
            [ db.tag(ea, name, value) for name, value in six.iteritems(new) if state.get(name, dummy) != value ]
        except:
            logging.warn("{:s}.apply(...{:s}) : {:#x} : Unable to apply tags to location: {!r}".format(__name__, tagmap_output, ea, new), exc_info=True)
        continue

    ## Now we can try updated frames
    print >>output, "--> Applying frames to each function... ({:d} entr{:s})".format(len(frames), 'y' if len(frames) == 1 else 'ies')
    for ea, res in sorted(six.iteritems(frames), key=first):
        ui.navigation.procedure(ea)
        try:
            apply_frame(ea, res, **tagmap)
        except:
            logging.warn("{:s}.apply(...{:s}) : {:#x} : Unable to apply tags to frame: {!r}".format(__name__, tagmap_output, ea, res), exc_info=True)
        continue
    return

def export(*tags, **boolean):
    '''Return the selected tags within the database as (globals, contents, {}).'''
    def globals(*tags, **boolean):
        for ea, res in db.select(*tags, **boolean):
            ui.navigation.auto(ea)
            yield ea, res
        return

    def contents(*tags, **boolean):
        for res in db.selectcontents(*tags, **boolean):
            for ea, res in func.select(*res):
                ui.navigation.set(ea)
                yield ea, res
            continue
        return

    print >>output, '--> Grabbing globals...'
    g = {ea : res for ea, res in itertools.ifilter(None, globals(*tags, **boolean))}
    print >>output, '--> Grabbing contents from functions...'
    c = {ea : res for ea, res in itertools.ifilter(None, contents(*tags, **boolean))}
    return g, c, {}

def list():
    '''Return all the contents tags within the database as a set.'''
    return {t for t in itertools.chain(*(t for _, t in db.selectcontents()))}
