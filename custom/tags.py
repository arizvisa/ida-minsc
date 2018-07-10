import six, sys, logging
import functools,operator,itertools,types,string

import database as db, function as func, structure as struc, ui
import internal

output = sys.stderr

### miscellaneous tag utilities
def list():
    '''Return all the contents tags within the database as a set.'''
    return {res for res in itertools.chain(*(res for _, res in db.selectcontents()))}

### internal utility functions and classes
def lvarNameQ(name):
    '''Determine whether a name is something that ida named automatically.'''
    if any(name.startswith(n) for n in ('arg_', 'var_')):
        res = name.split('_', 2)[-1]
        return all(n in string.hexdigits for n in res)
    elif name.startswith(' '):
        return name[1:] in {'s', 'r'}
    return False

def locationToAddress(loc):
    '''Convert the function location ``loc`` to an address.'''

    ## if location is a tuple, then convert it to an address
    if isinstance(loc, tuple):
        f, cid, ofs = loc
        base, _ = next(b for i, b in enumerate(func.chunks(f)) if i == cid)
        return base + ofs

    ## otherwise, it's already an address
    return loc

def addressToLocation(ea, chunks=None):
    """Convert the address ``ea`` to a (function, chunkid, offset).
    If the list ``chunks`` is specified, then use them as a tuple of ranges to calculate the offset.
    """
    F, chunks = func.by(ea), chunks or [ch for ch in func.chunks(ea)]
    cid, base = next((i, l) for i, (l, r) in enumerate(chunks) if l <= ea < r)
    return func.top(F), cid, ea - base

class dummy(object):
    '''Dummy object that always returns False when compared.'''
    def __eq__(self, other): return False
    def __cmp__(self, other): return -1
dummy = dummy()

### reading/writing tags from contents
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

def functions(use_cache=False, use_offset=False):
    """Yields all the function contents for each function within the database.
    If ``use_cache`` is specified, then just read it from the tagcache.
    If ``use_offset`` is specified, then yield the (FunctionEA, ChunkId, Offset) as the key.
    """
    everything = (ea for ea, _ in db.selectcontents()) if use_cache else iter(db.functions())

    ## Iterate through each function in the database
    for ea in everything:

        ## it's faster to precalculate this
        F, chunks = func.by(ea), [ch for ch in func.chunks(F)]

        ## Iterate through the function's contents yielding each tag
        for ea, res in function(ea, use_cache=use_cache):
            loc = addressToLocation(ea, chunks=chunks) if use_offset else ea
            yield loc, res
        continue
    return

def apply_functions(Contents, **tagmap):
    '''Apply ``Contents`` to the database using ``tagmap`` to alter the tag names before applying them.'''
    tagmap_output = ", {:s}".format(', '.join("{:s}={:s}".format(oldtag, newtag) for oldtag, newtag in six.iteritems(tagmap))) if tagmap else ''

    count = 0
    for loc, res in Contents:
        ea = locationToAddress(loc)

        ## warn the user if this address is not within a function
        if not func.within(ea):
            logging.warn("{:s}.apply_functions(...{:s}) : Address {:#x} is not within a function. Using a global tag.".format(__name__))

        ## grab the current (old) tag state
        state = db.tag(ea)

        ## transform the new tag state using the tagmap
        new = { tagmap.get(name, name) : value for name, value in six.viewitems(res) }

        ## check if the tag mapping resulted in the deletion of a tag
        if len(new) != len(res):
            for name in six.viewkeys(res) - six.viewkeys(new):
                logging.warn("{:s}.apply_functions(...{:s}) : {:#x} : Refusing requested tag mapping as it results in tag {!r} overwriting tag {!r} for a contents tag: {!r} -> {!r}".format(__name__, tagmap_output, ea, tagmap[name], name, res[tagmap[name]], res[name]))
            pass

        ## inform the user if any tags are being overwritten with different values
        for name in six.viewkeys(state) & six.viewkeys(new):
            if state[name] == new[name]: continue
            logging.warn("{:s}.apply_functions(...{:s}) : {:#x} : Overwriting contents tag {!r} with new value: {!r} -> {!r}".format(__name__, tagmap_output, ea, name, state[name], new[name]))

        ## write the tags to the contents address
        try:
            [ db.tag(ea, name, value) for name, value in six.iteritems(new) if state.get(name, dummy) != value ]
        except:
            logging.warn("{:s}.apply_functions(...{:s}) : {:#x} : Unable to apply tags to location: {!r}".format(__name__, tagmap_output, ea, new), exc_info=True)

        ## increase our counter
        count += 1
    return count

### reading/writing tags from globals
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

def apply_globals(Globals, **tagmap):
    '''Apply ``Globals`` to the database using ``tagmap`` to alter the tag names before applying them.'''
    tagmap_output = ", {:s}".format(', '.join("{:s}={:s}".format(oldtag, newtag) for oldtag, newtag in six.iteritems(tagmap))) if tagmap else ''

    count = 0
    for ea, res in Globals:
        ns = func if func.within(ea) else db

        ## grab the current (old) tag state
        state = ns.tag(ea)

        ## transform the new tag state using the tagmap
        new = { tagmap.get(name, name) : value for name, value in six.viewitems(res) }

        ## check if the tag mapping resulted in the deletion of a tag
        if len(new) != len(res):
            for name in six.viewkeys(res) - six.viewkeys(new):
                logging.warn("{:s}.apply_globals(...{:s}) : {:#x} : Refusing requested tag mapping as it results in tag {!r} overwriting tag {!r} for a global tag: {!r} -> {!r}".format(__name__, tagmap_output, ea, tagmap[name], name, res[tagmap[name]], res[name]))
            pass

        ## check what's going to be overwritten with different values prior to doing it
        for name in six.viewkeys(state) & six.viewkeys(new):
            if state[name] == new[name]: continue
            logging.warn("{:s}.apply_globals(...{:s}) : {:#x} : Overwriting global tag {!r} with new value: {!r} -> {!r}".format(__name__, tagmap_output, ea, name, state[name], new[name]))

        ## now we can apply the tags to the global address
        try:
            [ ns.tag(ea, name, value) for name, value in six.iteritems(new) if state.get(name, dummy) != value ]
        except:
            logging.warn("{:s}.apply_globals(...{:s}) : {:#x} : Unable to apply tags to global: {!r}".format(__name__, tagmap_output, ea, new), exc_info=True)

        ## increase our counter
        count += 1
    return count

### reading/writing tags from frames
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

def frames():
    '''Yields all the frames for each function within the database.'''
    for ea in db.functions():
        ui.navigation.procedure(ea)

        ## grab the frame
        res = dict(frame(ea))

        ## if something is there, then yield it
        if res: yield ea, res
    return

def apply_frames(Frames, **tagmap):
    '''Apply ``Frames`` to the database using ``tagmap`` to alter the tag names before applying them.'''
    tagmap_output = ", {:s}".format(', '.join("{:s}={:s}".format(oldtag, newtag) for oldtag, newtag in six.iteritems(tagmap))) if tagmap else ''

    count = 0
    for ea, res in Frames:
        try:
            apply_frame(ea, res, **tagmap)
        except:
            logging.warn("{:s}.apply_frames(...{:s}) : {:#x} : Unable to apply tags to frame: {!r}".format(__name__, tagmap_output, ea, res), exc_info=True)

        ## increase our counter
        count += 1
    return count

### reading everything from the entire database
def __read_cached(use_offset=False):
    '''Return all tags using the database's tag cache as (Globals, Contents).'''

    ## grab all globals that're cached
    print >>output, '--> Grabbing globals (cached)...'
    Globals = dict(globals(use_cache=True))

    ## grab any contents that're cached
    print >>output, '--> Grabbing contents from all functions (cached)...'
    Contents = dict(functions(use_cache=True, use_offset=use_offset))

    return Globals, Contents

def __read_uncached(use_offset=False):
    '''Return all tags within the database as (Globals, Contents).'''

    print >>output, '--> Grabbing globals...'
    Globals = dict(globals(use_cache=False))

    print >>output, '--> Grabbing contents from all functions...'
    Contents = dict(functions(use_cache=False, use_offset=use_offset))

    return Globals, Contents

def read(use_cache=False, use_offset=False):
    '''Return all the tags within the database as (Globals, Contents, Frames).'''
    f = __read_cached if use_cache else __read_uncached

    ## read the globals and the contents
    Globals, Contents = f(use_offset=use_offset)

    ## read the frames
    print >>output, '--> Grabbing frames from all functions...'
    Frames = {ea : res for ea, res in frames()}

    ## return everything back to the user
    return Globals, Contents, Frames

### apply everything to the entire database
def apply((Globals, Contents, Frames), **tagmap):
    '''Write all the tags from (Globals, Contents, Frames) into the database.'''
    first = operator.itemgetter(0)

    ## convert a sorted list keyed by an address into something that updates ida's navigation pointer
    def update_navigation(xs, setter):
        '''Call ``setter`` on ea for each iteration of list ``xs``.'''
        for x in xs:
            ea, _ = x
            setter(ea)
            yield x
        return

    ## convert a sorted list keyed by a location into something that updates ida's navigation pointer
    def update_navigation_contents(xs, setter):
        '''Call ``setter`` on location for each iteration of list ``xs``.'''
        for x in xs:
            loc, _ = x
            ea = locationToAddress(loc)
            setter(ea)
            yield x
        return

    ## handle globals
    print >>output, "--> Writing globals... ({:d} entr{:s})".format(len(Globals), 'y' if len(Globals) == 1 else 'ies')
    iterable = sorted(six.iteritems(Globals), key=first)
    res = apply_globals(update_navigation(iterable, ui.navigation.auto), **tagmap)

    ## handle contents
    print >>output, "--> Writing function contents... ({:d} entr{:s})".format(len(Contents), 'y' if len(Contents) == 1 else 'ies')
    iterable = sorted(six.iteritems(Contents), key=first)
    res = apply_functions(update_navigation_contents(iterable, ui.navigation.set), **tagmap)

    ## update any frames
    print >>output, "--> Applying frames to each function... ({:d} entr{:s})".format(len(Frames), 'y' if len(Frames) == 1 else 'ies')
    iterable = sorted(six.iteritems(Frames), key=first)
    res = apply_frames(update_navigation(iterable, ui.navigation.procedure), **tagmap)

    return

### query a function for content or frame members that match the specified tags
def export_content(F, *tags, **use_offset):
    """Select all the content tags in function ``F`` that match the specified ``tags``.
    If ``use_offset`` is specified, then yield the (FunctionEA, ChunkId, Offset) as the key.
    """
    identity = lambda res: res
    transform = addressToLocation if use_offset.get('use_offset', False) else identity

    for ea, res in func.select(F, Or=tags) if tags else func.select(F):
        ui.navigation.set(ea)
        if res: yield transform(ea), res
    return

def export_frame(F, *tags):
    '''Select all the members and their tags in the frame for function ``F`` that match the specified ``tags``.'''
    tags_ = { tag for tag in tags }

    for ofs, item in frame(F):
        field, type, comment = item

        # if the entire comment is in tags (like None) or no tags were specified, then save the entire member
        if not tags or comment in tags_:
            yield ofs, item
            continue

        # otherwise, decode the comment into a dictionary using only the tags the user asked for
        comment_ = internal.comment.decode(comment)
        res = { name : comment_[name] for name in six.viewkeys(comment_) & tags_ }

        # if anything was found, then re-encode it and yield to the user
        if res: yield ofs, (field, type, internal.comment.encode(res))
    return

### query the database for the desired components
def export_globals(*tags):
    '''Select all the global tags that match the specified ``tags``.'''
    for ea, res in db.select(Or=tags) if tags else db.select():
        ui.navigation.auto(ea)
        if res: yield ea, res
    return

def export_contents(*tags, **use_offset):
    """Select all the contents tags in the database that match the specified ``tags``.
    If ``use_offset`` is specified, then yield the (FunctionEA, ChunkId, Offset) as the key.
    """
    use_offset = use_offset.get('use_offset', False)

    for F, res in db.selectcontents(Or=tags) if tags else db.selectcontents():
        for loc, res in export_content(F, *res, use_offset=use_offset):
            if res: yield loc, res
        continue
    return

def export_frames(*tags):
    '''Select all the frames in the database that match the specified ``tags``.'''
    tags_ = {x for x in tags}

    for ea in db.functions():
        ui.navigation.procedure(ea)

        ## grab the frame
        res = dict(export_frame(ea, *tags))

        ## if something is there, then yield it
        if res: yield ea, res
    return

def export(*tags, **use_offset):
    """Return the selected tags within the database as (Globals, Contents, Frames).
    If ``use_offset`` is set to True, then yield the Contents keyed by its location.
    """

    identity = lambda res: res

    ## collect all the globals into a dictionary
    print >>output, '--> Grabbing globals...'
    iterable = export_globals(*tags)
    Globals = {ea : res for ea, res in itertools.ifilter(None, iterable)}

    ## grab all the contents into a dictionary
    print >>output, '--> Grabbing contents from functions...'
    use_offset = use_offset.get('use_offset', False)
    iterable = export_contents(*tags, use_offset=use_offset)
    Contents = {loc : res for loc, res in itertools.ifilter(None, iterable)}

    ## grab any frames into a dictionary
    iterable = export_frames(*tags)
    Frames = {ea : res for ea, res in iterable.ifilter(None, iterable)}

    ## return it back to the user
    return Globals, Contents, Frames
