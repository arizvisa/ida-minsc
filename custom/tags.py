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

### read without using the tag cache
class read(object):
    """
    Reading all the tags from within the database without using the tag cache.
    """

    def __new__(cls, location=False):
        return cls.everything(location=location)

    ## reading the content from a function
    @classmethod
    def content(cls, ea):
        '''Yield every tag defined within a function.'''
        F = func.by(ea)

        # iterate through every address in the function
        for ea in func.iterate(F):
            ui.navigation.set(ea)

            # yield the tags
            res = db.tag(ea)
            if res: yield ea, res
        return

    ## reading the tags from a frame
    @classmethod
    def frame(cls, ea):
        '''Yield each field within the frame belonging to the function ``ea``'''
        F = func.by(ea)

        # iterate through all of the frame's members
        res = func.frame(F)
        for member in res.members:
            # if ida has named it and there's no comment, then skip
            if lvarNameQ(member.name) and not member.comment:
                continue

            # if it's a structure, then the type is the structure name
            if isinstance(member.type, struc.structure_t):
                logging.info("{:s}.frame({:#x}) : Storing structure-based type as name for field {:+#x} : {!r}".format('.'.join((__name__, cls.__name__)), ea, member.offset, member.type))
                type = member.type.name

            # otherwise, the type is a tuple that we can serializer
            else:
                type = member.type

            # otherwise, it's just a regular field. so we can just save what's important.
            yield member.offset, (member.name, type, member.comment)
        return

    ## reading everything from the entire database
    @classmethod
    def everything(cls, location=False):
        """Return all the tags within the database as (Globals, Contents, Frames).
        If ``location`` is specified, then store the key for the contents tags as a relative location.
        """
        global read

        # read the globals and the contents
        print >>output, '--> Grabbing globals...'
        Globals = { ea : res for ea, res in read.globals() }

        # read all content
        print >>output, '--> Grabbing contents from all functions...'
        Contents = { loc : res for loc, res in read.contents(location=location) }

        # read the frames
        print >>output, '--> Grabbing frames from all functions...'
        Frames = {ea : res for ea, res in read.frames()}

        # return everything back to the user
        return Globals, Contents, Frames

    ## reading the globals from the database
    @staticmethod
    def globals():
        '''Yields all the globally defined tags.'''
        ea, sentinel = db.config.bounds()

        # loop till we hit the end of the database
        while ea < sentinel:
            ui.navigation.auto(ea)
            funcQ = func.within(ea)

            # figure out which tag function to use
            f = func.tag if funcQ else db.tag

            # grab the tag and yield it
            res = f(ea)
            if res: yield ea, res

            # if we're in a function, then seek to the next chunk
            if funcQ:
                _, ea = func.chunk(ea)
                continue

            # otherwise, try the next address till we hit a sentinel value
            try: ea = db.a.next(ea)
            except StandardError: ea = sentinel
        return

    ## reading the contents from the entire database
    @staticmethod
    def contents(location=False):
        """Yields all the contents of each function within the database.
        If ``location`` is specified, then yield a location relative to the function chunk as the key.
        """
        global read

        # Iterate through each function in the database
        for ea in db.functions():

            # it's faster to precalculate the chunks here
            F, chunks = func.by(ea), [ch for ch in func.chunks(ea)]

            # Iterate through the function's contents yielding each tag
            for ea, res in read.content(ea):
                loc = addressToLocation(ea, chunks=chunks) if location else ea
                yield loc, res
            continue
        return

    ## reading the frames from the entire database
    @staticmethod
    def frames():
        '''Yields all the frames for each function within the database.'''
        global read

        for ea in db.functions():
            ui.navigation.procedure(ea)
            res = dict(read.frame(ea))
            if res: yield ea, res
        return

### Applying tags to the database
class apply(object):
    """
    Apply tags that have been exported back into the current database.
    """

    def __new__(cls, (Globals, Contents, Frames), **tagmap):
        res = Globals, Contents, Frames
        return cls.everything(res, **tagmap)

    ## applying the content to a function
    @classmethod
    def content(cls, Contents, **tagmap):
        '''Apply ``Contents`` to the database using ``tagmap`` to alter the tag names before applying them.'''
        global apply
        return apply.contents(Contents, **tagmap)

    ## applying a frame to a function
    @classmethod
    def frame(cls, ea, frame, **tagmap):
        """Apply the data in ``frame`` to the function at ``ea``.
        If ``tagmap`` is specified, map the tags being applied through it.
        """
        tagmap_output = ", {:s}".format(', '.join("{:s}={:s}".format(k, v) for k, v in six.iteritems(tagmap))) if tagmap else ''

        F = func.frame(ea)
        for offset, (name, type, comment) in six.iteritems(frame):
            try:
                member = F.by_offset(offset)
            except LookupError:
                logging.warn("{:s}.frame({:#x}, ...{:s}) : Unable to find frame member at {:+#x}. Skipping application of data to it. : {!r}".format('.'.join((__name__, cls.__name__)), ea, tagmap_output, offset, (name, type, comment)))
                continue

            if member.name != name:
                if any(not member.name.startswith(n) for n in ('arg_','var_',' ')):
                    logging.warn("{:s}.frame({:#x}, ...{:s}) : Renaming frame member {:+#x} with new name. : {!r} -> {!r}".format('.'.join((__name__, cls.__name__)), ea, tagmap_output, offset, member.name, name))
                member.name = name

            # check what's going to be overwritten with different values prior to doing it
            state, res = map(internal.comment.decode, (member.comment, comment))

            # transform the new tag state using the tagmap
            new = { tagmap.get(name, name) : value for name, value in six.viewitems(res) }

            # check if the tag mapping resulted in the deletion of a tag
            if len(new) != len(res):
                for name in six.viewkeys(res) - six.viewkeys(new):
                    logging.warn("{:s}.frame({:#x}, ...{:s}) : Refusing requested tag mapping as it results in tag {!r} overwriting tag {!r} for frame member {:+#x}: {!r} -> {!r}".format('.'.join((__name__, cls.__name__)), ea, tagmap_output, tagmap[name], name, offset, res[tagmap[name]], res[name]))
                pass

            # warn the user about what's going to be overwritten prior to doing it
            for name in six.viewkeys(state) & six.viewkeys(new):
                if state[name] == new[name]: continue
                logging.warn("{:s}.frame({:#x}, ...{:s}) : Overwriting tag {!r} for frame member {:+#x} with new value. : {!r} -> {!r}".format('.'.join((__name__, cls.__name__)), ea, tagmap_output, name, offset, state[name], new[name]))

            # now we can update the current dictionary
            mapstate = { name : value for name, value in six.iteritems(new) if state.get(name, dummy) != value }
            state.update(mapstate)

            # convert it back to a multi-lined comment and assign it
            member.comment = internal.comment.encode(state)

            # if the type is a string, then figure out which structure to use
            if isinstance(type, basestring):
                try:
                    member.type = struc.by(type)
                except LookupError:
                    logging.warn("{:s}.frame({:#x}, ...{:s}): Unable to find structure {!r} for member at {:+#x}. Skipping. it.".format('.'.join((__name__, cls.__name__)), ea, tagmap_output, type, offset))

            # otherwise, it's a pythonic tuple that we can just assign
            else:
                member.type = type
            continue
        return

    ## apply everything to the entire database
    @classmethod
    def everything(cls, (Globals, Contents, Frames), **tagmap):
        '''Apply all the tags from (Globals, Contents, Frames) into the database.'''
        global apply

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
        iterable = sorted(six.iteritems(Globals), key=operator.itemgetter(0))
        res = apply.globals(update_navigation(iterable, ui.navigation.auto), **tagmap)
        # FIXME: verify that res matches number of Globals

        ## handle contents
        print >>output, "--> Writing function contents... ({:d} entr{:s})".format(len(Contents), 'y' if len(Contents) == 1 else 'ies')
        iterable = sorted(six.iteritems(Contents), key=operator.itemgetter(0))
        res = apply.contents(update_navigation_contents(iterable, ui.navigation.set), **tagmap)
        # FIXME: verify that res matches number of Contents

        ## update any frames
        print >>output, "--> Applying frames to each function... ({:d} entr{:s})".format(len(Frames), 'y' if len(Frames) == 1 else 'ies')
        iterable = sorted(six.iteritems(Frames), key=operator.itemgetter(0))
        res = apply.frames(update_navigation(iterable, ui.navigation.procedure), **tagmap)
        # FIXME: verify that res matches number of Frames

        return

    ## applying tags to the globals
    @staticmethod
    def globals(Globals, **tagmap):
        '''Apply ``Globals`` to the database using ``tagmap`` to alter the tag names before applying them.'''
        global apply
        cls, tagmap_output = apply.__class__, ", {:s}".format(', '.join("{:s}={:s}".format(oldtag, newtag) for oldtag, newtag in six.iteritems(tagmap))) if tagmap else ''

        count = 0
        for ea, res in Globals:
            ns = func if func.within(ea) else db

            # grab the current (old) tag state
            state = ns.tag(ea)

            # transform the new tag state using the tagmap
            new = { tagmap.get(name, name) : value for name, value in six.viewitems(res) }

            # check if the tag mapping resulted in the deletion of a tag
            if len(new) != len(res):
                for name in six.viewkeys(res) - six.viewkeys(new):
                    logging.warn("{:s}.globals(...{:s}) : {:#x} : Refusing requested tag mapping as it results in tag {!r} overwriting tag {!r} for a global tag: {!r} -> {!r}".format('.'.join((__name__, cls.__name__)), tagmap_output, ea, tagmap[name], name, res[tagmap[name]], res[name]))
                pass

            # check what's going to be overwritten with different values prior to doing it
            for name in six.viewkeys(state) & six.viewkeys(new):
                if state[name] == new[name]: continue
                logging.warn("{:s}.globals(...{:s}) : {:#x} : Overwriting global tag {!r} with new value: {!r} -> {!r}".format('.'.join((__name__, cls.__name__)), tagmap_output, ea, name, state[name], new[name]))

            # now we can apply the tags to the global address
            try:
                [ ns.tag(ea, name, value) for name, value in six.iteritems(new) if state.get(name, dummy) != value ]
            except:
                logging.warn("{:s}.globals(...{:s}) : {:#x} : Unable to apply tags to global: {!r}".format('.'.join((__name__, cls.__name__)), tagmap_output, ea, new), exc_info=True)

            # increase our counter
            count += 1
        return count

    ## applying contents tags to all the functions
    @staticmethod
    def contents(Contents, **tagmap):
        '''Apply ``Contents`` to the database using ``tagmap`` to alter the tag names before applying them.'''
        global apply
        cls, tagmap_output = apply.__class__, ", {:s}".format(', '.join("{:s}={:s}".format(oldtag, newtag) for oldtag, newtag in six.iteritems(tagmap))) if tagmap else ''

        count = 0
        for loc, res in Contents:
            ea = locationToAddress(loc)

            # warn the user if this address is not within a function
            if not func.within(ea):
                logging.warn("{:s}.contents(...{:s}) : Address {:#x} is not within a function. Using a global tag.".format('.'.join((__name__, cls.__name__))))

            # grab the current (old) tag state
            state = db.tag(ea)

            # transform the new tag state using the tagmap
            new = { tagmap.get(name, name) : value for name, value in six.viewitems(res) }

            # check if the tag mapping resulted in the deletion of a tag
            if len(new) != len(res):
                for name in six.viewkeys(res) - six.viewkeys(new):
                    logging.warn("{:s}.contents(...{:s}) : {:#x} : Refusing requested tag mapping as it results in tag {!r} overwriting tag {!r} for a contents tag: {!r} -> {!r}".format('.'.join((__name__, cls.__name__)), tagmap_output, ea, tagmap[name], name, res[tagmap[name]], res[name]))
                pass

            # inform the user if any tags are being overwritten with different values
            for name in six.viewkeys(state) & six.viewkeys(new):
                if state[name] == new[name]: continue
                logging.warn("{:s}.contents(...{:s}) : {:#x} : Overwriting contents tag {!r} with new value: {!r} -> {!r}".format('.'.join((__name__, cls.__name__)), tagmap_output, ea, name, state[name], new[name]))

            # write the tags to the contents address
            try:
                [ db.tag(ea, name, value) for name, value in six.iteritems(new) if state.get(name, dummy) != value ]
            except:
                logging.warn("{:s}.contents(...{:s}) : {:#x} : Unable to apply tags to location: {!r}".format('.'.join((__name__, cls.__name__)), tagmap_output, ea, new), exc_info=True)

            # increase our counter
            count += 1
        return count

    ## applying frames to all the functions
    @staticmethod
    def frames(Frames, **tagmap):
        '''Apply ``Frames`` to the database using ``tagmap`` to alter the tag names before applying them.'''
        global apply
        cls, tagmap_output = apply.__class__, ", {:s}".format(', '.join("{:s}={:s}".format(oldtag, newtag) for oldtag, newtag in six.iteritems(tagmap))) if tagmap else ''

        count = 0
        for ea, res in Frames:
            try:
                apply.frame(ea, res, **tagmap)
            except:
                logging.warn("{:s}.frames(...{:s}) : {:#x} : Unable to apply tags to frame: {!r}".format('.'.join((__name__, cls.__name__)), tagmap_output, ea, res), exc_info=True)

            # increase our counter
            count += 1
        return count

### Exporting tags from the database using the tag cache
class export(object):
    """
    Query the database using the tagcache.
    """

    def __new__(cls, *tags, **location):
        return cls.everything(*tags, **location)

    ## query the content from a function
    @classmethod
    def content(cls, F, *tags, **location):
        """Select all the content tags in function ``F`` that match the specified ``tags`` by using the tag cache.
        If ``location`` is specified, then yield a relative location based on (FunctionEA, ChunkId, Offset) as the key.
        """
        identity = lambda res: res
        transform = addressToLocation if location.get('location', False) else identity

        iterable = func.select(F, Or=tags) if tags else func.select(F)
        for ea, res in iterable:
            ui.navigation.set(ea)
            if res: yield transform(ea), res
        return

    ## query the frame from a function
    @classmethod
    def frame(cls, F, *tags):
        '''Select all the members and their tags in the frame for function ``F`` that match the specified ``tags``.'''
        global read, internal
        tags_ = { tag for tag in tags }

        for ofs, item in read.frame(F):
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

    ## query the entire database for the specified tags
    @classmethod
    def everything(cls, *tags, **location):
        """Return the selected tags using the tag cache as (Globals, Contents, Frames).
        If ``location`` is set to True, then yield the Contents keyed by its location.
        """
        global export

        # collect all the globals into a dictionary
        print >>output, '--> Grabbing globals (cached)...'
        iterable = export.globals(*tags)
        Globals = {ea : res for ea, res in itertools.ifilter(None, iterable)}

        # grab all the contents into a dictionary
        print >>output, '--> Grabbing contents from functions (cached)...'
        location = location.get('location', False)
        iterable = export.contents(*tags, location=location)
        Contents = {loc : res for loc, res in itertools.ifilter(None, iterable)}

        # grab any frames into a dictionary
        print >>output, '--> Grabbing frames from functions (cached)...'
        iterable = export.frames(*tags)
        Frames = {ea : res for ea, res in itertools.ifilter(None, iterable)}

        # return it back to the user
        return Globals, Contents, Frames

    ## query all the globals matching the specified tags
    @staticmethod
    def globals(*tags):
        '''Select all the global tags from the tag cache that match the specified ``tags``.'''
        iterable = db.select(Or=tags) if tags else db.select()
        for ea, res in iterable:
            ui.navigation.auto(ea)
            if res: yield ea, res
        return

    ## query all the contents in each function that match the specified tags
    @staticmethod
    def contents(*tags, **location):
        """Return all the contents tags (using the tag cache) that match the specified ``tags``.
        If ``location`` is specified, then yield the (FunctionEA, ChunkId, Offset) as the key.
        """
        global export
        location = location.get('location', False)

        iterable = db.selectcontents(Or=tags) if tags else db.selectcontents()
        for F, res in iterable:
            for loc, res in export.content(F, *res, location=location):
                if res: yield loc, res
            continue
        return

    ## query all the frames that match the specified tags
    @staticmethod
    def frames(*tags):
        '''Select all the frames in the database that match the specified ``tags``.'''
        global export
        tags_ = {x for x in tags}

        for ea in db.functions():
            ui.navigation.procedure(ea)
            res = dict(export.frame(ea, *tags))
            if res: yield ea, res
        return
