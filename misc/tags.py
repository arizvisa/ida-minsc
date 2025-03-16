"""
Tags module (internal)

This module is used for reading and writing tags to an address, function,
structure, or structure member within the database. It primarily revolves
around the tools provided by either the `internal.tagcache` or the newer
`internal.tagindex` modules. These modules are responsible for maintaining
any of the indices or caches that are necessary for performance.
"""
import logging, functools, operator, itertools
import idaapi, internal, internal.tagcache, internal.tagindex
from internal import utils, interface, declaration, comment
logging = logging.getLogger(__name__)

class query_v0(object):
    """
    This namespace is used to query different types of tags from the tagcache
    and yield the results to the caller. Its purpose is to return raw
    unprocessed numbers rather than user-friendly types representing the results
    of the selection. This is intended to be used by the matchers which can be
    used to filter the results of certain types of artifacts.

    Filtering of the results from the functions in this namespace is done by
    specifying a group of "required" tags, which must exist for the location to
    be yielded, and/or a group of "included" tags which will be included in the
    yielded result if they are found. If no "required" or "included" tags are
    specified, then all of the results from the tagcache will be yielded.
    """
    navigation = __import__('ui').navigation

    @classmethod
    def globals(cls, required=[], included=[]):
        '''Query the globals in the database and yield a tuple containing its address and all of the `required` tags with any `included` ones.'''
        iterable = required if isinstance(required, (internal.types.unordered, internal.types.dictionary)) else {required}
        required = {key for key in iterable}
        iterable = included if isinstance(included, (internal.types.unordered, internal.types.dictionary)) else {included}
        included = {key for key in iterable}

        # Nothing specific was queried, so just yield all tags that are available.
        if not(required or included):
            for ea in internal.tagcache.globals.address():
                cls.navigation.set(ea)
                Ftag, owners = (function.get, {f for f in interface.function.owners(ea)}) if interface.function.has(ea) else (address.get, {ea})
                tags = Ftag(ea)
                if tags and ea in owners: yield ea, tags
                elif ea not in owners: logging.info(u"{:s}.database({!s}, {!s}) : Refusing to yield {:d} global tag{:s} for {:s} ({:#x}) possibly due to cache inconsistency as it is not referencing one of the candidate locations ({:s}).".format('.'.join([__name__, cls.__name__]), sorted(required), sorted(included), len(tags), '' if len(tags) == 1 else 's', 'function address' if interface.function.has(ea) else 'address', ea, ', '.join(map("{:#x}".format, owners))))
            return

        # Walk through every tagged address so we can cross-check them with the query.
        for ea in internal.tagcache.globals.address():
            Ftag, owners = (function.get, {f for f in interface.function.owners(ea)}) if interface.function.has(ea) else (address.get, {ea})
            tags = Ftag(cls.navigation.set(ea))

            # included is the equivalent of Or(|) and yields the address if any of the tagnames are used.
            collected = {key : value for key, value in tags.items() if key in included}

            # required is the equivalent of And(&) which yields the address only if it uses all of the specified tagnames.
            if required:
                if required & {tag for tag in tags} == required:
                    collected.update({key : value for key, value in tags.items() if key in required})
                else: continue

            # If we collected anything (matches), then yield the address and the matching tags.
            if collected and ea in owners: yield ea, collected
            elif ea not in owners: logging.info(u"{:s}.database({!s}, {!s}) : Refusing to select from {:d} global tag{:s} for {:s} ({:#x}) possibly due to cache inconsistency as it is not referencing one of the candidate locations ({:s}).".format('.'.join([__name__, cls.__name__]), sorted(required), sorted(included), len(tags), '' if len(tags) == 1 else 's', 'function address' if interface.function.has(ea) else 'address', ea, ', '.join(map("{:#x}".format, owners))))
        return

    @classmethod
    def contents(cls, required=[], included=[]):
        '''Query the contents of each function and yield a tuple containing its address and all of the `required` tags with any `included` ones.'''
        iterable = required if isinstance(required, (internal.types.unordered, internal.types.dictionary)) else {required}
        required = {key for key in iterable}
        iterable = included if isinstance(included, (internal.types.unordered, internal.types.dictionary)) else {included}
        included = {key for key in iterable}

        # Nothing specific was queried, so just yield all tagnames that are available.
        if not(required or included):
            for ea, _ in internal.tagcache.contents.iterate():
                if interface.function.has(cls.navigation.procedure(ea)):
                    owners, Flogging = {f for f in interface.function.owners(ea)}, logging.info
                    contents = internal.tagcache.contents.name(ea, target=ea)
                else:
                    owners, Flogging = {f for f in []}, logging.warning
                    contents = []
                if contents and ea in owners: yield ea, contents
                elif ea not in owners: Flogging(u"{:s}.contents({!s}, {!s}) : Refusing to yield {:d} contents tag{:s} for {:s} ({:#x}) possibly due to cache inconsistency as it is not referencing {:s}.".format('.'.join([__name__, cls.__name__]), sorted(required), sorted(included), len(contents), '' if len(contents) == 1 else 's', 'function address' if interface.function.has(ea) else 'address', ea, "a candidate function address ({:s})".format(', '.join(map("{:#x}".format, owners)) if owners else 'a function')))
            return

        # Walk through the index verifying that they're within a function. This way
        # we can cross-check their cache against the user's query. If we're not
        # in a function then the cache is lying and we need to skip this iteration.
        for ea, cache in internal.tagcache.contents.iterate():
            if not interface.function.has(cls.navigation.procedure(ea)):
                logging.warning(u"{:s}.contents({!s}, {!s}) : Detected cache inconsistency where address ({:#x}) should be referencing a function.".format('.'.join([__name__, cls.__name__]), sorted(required), sorted(included), ea))
                continue

            # Now start aggregating the tagnames that the user is searching for.
            owners = {item for item in interface.function.owners(ea)}
            names = internal.tagcache.contents.name(ea, target=ea)

            # included is the equivalent of Or(|) and yields the function address if any of the specified tagnames were used.
            collected = included & names

            # required is the equivalent of And(&) which yields the function address only if it uses all of the specified tagnames.
            if required:
                if required & names == required:
                    collected.update(required)
                else: continue

            # If anything was collected (tagnames were matched), then yield the
            # address along with the matching tagnames.
            if collected and ea in owners: yield ea, collected
            elif ea not in owners: logging.info(u"{:s}.contents({!s}, {!s}) : Refusing to select from {:d} contents tag{:s} for {:s} address ({:#x}) possibly due to cache inconsistency as it is not referencing {:s}.".format('.'.join([__name__, cls.__name__]), sorted(required), sorted(included), len(names), '' if len(names) == 1 else 's', 'function', ea, "a candidate function address ({:s})".format(', '.join(map("{:#x}".format, owners)) if owners else 'a function')))
        return

    @classmethod
    def function(cls, func, required=[], included=[]):
        '''Query the contents of the function `func` and yield a tuple containing each address and all of the `required` tags with any `included` ones.'''
        iterable = required if isinstance(required, (internal.types.unordered, internal.types.dictionary)) else {required}
        required = {key for key in iterable}
        iterable = included if isinstance(included, (internal.types.unordered, internal.types.dictionary)) else {included}
        included = {key for key in iterable}

        # First thing is to convert the argument to a proper function to query.
        target = interface.function.by(func)

        # If nothing specific was queried, then yield all tags that are available.
        if not(required or included):
            for ea in internal.tagcache.contents.address(interface.range.start(target), target=interface.range.start(target)):
                cls.navigation.analyze(ea)
                res = address.get(ea)
                if res: yield ea, res
            return

        # Walk through every tagged address and cross-check it against the query.
        for ea in internal.tagcache.contents.address(interface.range.start(target), target=interface.range.start(target)):
            res = address.get(cls.navigation.analyze(ea))

            # included is the equivalent of Or(|) and yields the address if any of the tagnames are used.
            collected = {key : value for key, value in res.items() if key in included}

            # required is the equivalent of And(&) which yields the addrss only if it uses all of the specified tagnames.
            if required:
                if required & {tag for tag in res} == required:
                    collected.update({key : value for key, value in res.items() if key in required})
                else: continue

            # If anything was collected (matched), then yield the address and the matching tags.
            if collected: yield ea, collected
        return

    @classmethod
    def structures(cls, required=[], included=[]):
        '''Query the structures in the database and yield a tuple containing each and all of the `required` tags with any `included` ones.'''
        iterable = required if isinstance(required, (internal.types.unordered, internal.types.dictionary)) else {required}
        required = {key for key in iterable}
        iterable = included if isinstance(included, (internal.types.unordered, internal.types.dictionary)) else {included}
        included = {key for key in iterable}

        # user doesn't want anything specific, so yield all of them and their tags.
        if not(required or included):
            for sptr in internal.structure.iterate():
                content = structure.get(sptr)

                # if the structure had some content (tags), then we have a match
                # and can yield the structure and its content to the user.
                if content:
                    yield sptr.id, content
                continue
            return

        # now we just slowly iterate through our structures looking for any matches.
        for sptr in internal.structure.iterate():
            content = structure.get(sptr)

            # included is the equivalent of Or(|) and yields the structure if any of the tagnames are used.
            collected = {key : value for key, value in content.items() if key in included}

            # required is the equivalent of And(&) which yields the structure only if it uses all of the tagnames.
            if required:
                if required & {tag for tag in content} == required:
                    collected.update({key : value for key, value in content.items() if key in required})
                else: continue

            # that's all folks.. yield it if you got it.
            if collected: yield sptr.id, collected
        return

    @classmethod
    def structure(cls, sid, required=[], included=[]):
        '''Query the structures in the database and yield a tuple containing each and all of the `required` tags with any `included` ones.'''
        iterable = required if isinstance(required, (internal.types.unordered, internal.types.dictionary)) else {required}
        required = {key for key in iterable}
        iterable = included if isinstance(included, (internal.types.unordered, internal.types.dictionary)) else {included}
        included = {key for key in iterable}

        # If there were no tags to filter with, then we're being asked to yield
        # everything. so, we do just that for every member in the structure.
        if not(required or included):
            for mowner, mindex, mptr in internal.structure.members.iterate(sid):
                content = member.get(mptr)
                if content:
                    yield mptr.id, content
                continue
            return

        # Otherwise, we iterate through the structure and yield its members.
        for mowner, mindex, mptr in internal.structure.members.iterate(sid):
            content = member.get(mptr)

            # Start out by collecting any tagnames that should be included which is similar to Or(|).
            collected = {key : value for key, value in content.items() if key in included}

            # Then we need to include any specific tags that are required which is similar to And(&).
            if required:
                if required & {tag for tag in content} == required:
                    collected.update({key : value for key, value in content.items() if key in required})
                else: continue

            # Easy to do and easy to yield.
            if collected: yield mptr.id, collected
        return

    @classmethod
    def owners(cls, required=[], included=[]):
        '''Query the members in the database and yield a tuple containing the owning structure and all of the `required` tags with any `included` ones.'''
        iterable = required if isinstance(required, (internal.types.unordered, internal.types.dictionary)) else {required}
        required = {key for key in iterable}
        iterable = included if isinstance(included, (internal.types.unordered, internal.types.dictionary)) else {included}
        included = {key for key in iterable}

        # If we weren't given anything to query with, then we need to yield
        # the members tags for every single structure that we can find.
        if not(required or included):
            for sptr in internal.structure.iterate():
                iterable = (member.get(mptr) for mowner, mindex, mptr in internal.structure.members.iterate(sptr.id))
                names = {tag for tag in itertools.chain(*iterable)}
                if names:
                    yield sptr.id, names
                continue
            return

        # If we were given something to query the members of each structure
        # with, then we first grab the tags for every single structure member.
        for sptr in internal.structure.iterate():
            iterable = (member.get(mptr) for mowner, mindex, mptr in internal.structure.members.iterate(sptr.id))
            names = {tag for tag in itertools.chain(*iterable)}

            # Then we select any of the tag names that we were asked to include.
            # If any tag names are required, make sure they exist and skip to
            # the next structure if they don't.
            collected = included & names
            if required:
                if required & names == required:
                    collected.update(required)
                else: continue

            # If we have anything left, then it is worth yielding to the caller.
            if collected:
                yield sptr.id, collected
            continue
        return

    @classmethod
    def members(cls, required=[], included=[]):
        '''Query the members in the database and yield a tuple containing the member and all of the `required` tags with any `included` ones.'''
        iterable = required if isinstance(required, (internal.types.unordered, internal.types.dictionary)) else {required}
        required = {key for key in iterable}
        iterable = included if isinstance(included, (internal.types.unordered, internal.types.dictionary)) else {included}
        included = {key for key in iterable}

        # If there were no parameters to filter with, then we can just yield
        # every tag that we find.
        if not(required or included):
            for sptr in internal.structure.iterate():
                for mowner, mindex, mptr in internal.structure.members.iterate(sptr.id):
                    content = member.get(mptr)

                    # If there's content for the member, then yield it.
                    # Otherwise we can continue to the next one.
                    if content:
                        yield mptr.id, content
                    continue
                continue
            return

        # If we were given something to query the members of each structure
        # with, then we first grab the tags for every single structure member.
        for sptr in internal.structure.iterate():
            for mowner, mindex, mptr in internal.structure.members.iterate(sptr.id):
                content = member.get(mptr)

                # Filter our tags for any that were specified to be included.
                collected = {key : value for key, value in content.items() if key in included}

                # Now check for all the tags that must be required. If we didn't
                # find a match, then continue onto the next member that we find.
                if required:
                    if required & {tag for tag in content} == required:
                        collected.update({key : value for key, value in content.items() if key in required})
                    else: continue

                # Check if our filtering left us some results and yield them.
                if collected:
                    yield mptr.id, collected
                continue
            continue
        return

    @classmethod
    def blocks(cls, func, required=[], included=[]):
        '''Query the basic blocks of the function `func` and yield a tuple containing the block and all of the `required` tags with any `included` ones.'''
        flags = getattr(idaapi, 'FC_NOEXT', 2) | getattr(idaapi, 'FC_CALL_ENDS', 0x20)
        fn = interface.function.by(func)
        ea = interface.range.start(fn)

        # Grab all of the blocks and build a map for their starting address. We
        # preserve the order so that we can yield results for our map in order.
        blockmap = [(interface.range.start(bb), bb) for bb in interface.function.blocks(fn, flags)]
        order = [ea for ea, _ in blockmap]
        blocks = {ea : bb for ea, bb in blockmap}

        # Now we just need to union our tagged addresses with the ones which
        # are basic-blocks to get a list of the addresses actually selected.
        available = {ea for ea in internal.tagcache.contents.address(ea, target=ea)}
        selected = {ea for ea in available} & {ea for ea in order}
        ordered = [ea for ea in order if ea in selected]

        # If nothing specific was queried, then iterate through our ordered
        # blocks and yield absolutely everything that we found.
        if not(required or included):
            for ea in ordered:
                res = block.get(blocks[cls.navigation.analyze(ea)])
                if res: yield blocks[ea], res
            return

        # Walk through every tagged address and cross-check it against the query.
        for ea in ordered:
            res = block.get(blocks[cls.navigation.analyze(ea)])

            # included is the equivalent of Or(|) and yields a block if any of the specified tagnames are used.
            collected = {key : value for key, value in res.items() if key in included}

            # required is the equivalent of And(&) which yields a block only if it uses all of the specified tagnames.
            if required:
                if required & {tag for tag in res} == required:
                    collected.update({key : value for key, value in res.items() if key in required})
                else: continue

            # If anything was collected (matched), then yield the block and the matching tags.
            if collected: yield blocks[ea], collected
        return

class select_v0(object):
    """
    This namespace is used to select different types of tags from the tagcache
    and yield the results to the caller. The information yielded to the caller
    is in the form of a tuple composed of the unique address or location of the
    tags, and then the tags themselves. The results of these functions can be
    used to create a dictionary by the caller if necessary. If no required or
    included tags are specified, the empty tag ("") and any dunder-prefixed tags
    are excluded.

    This specific implementation wraps the results of the `query_v0` namespace
    and post-processes the results to yield user-friendly types with the tags.
    """

    @classmethod
    def database(cls, *args):
        '''Query the globals in the database and yield a tuple containing its address and all of the `required` tags with any `included` ones.'''
        if args:
            for pair in query_v0.globals(*args):
                yield pair
            return

        # Nothing specific was queried, so just yield all tags that are
        # available while making sure to exclude any implicit ones.
        for ea, res in query_v0.globals(*args):
            explicit = {tag : value for tag, value in res.items() if tag and not tag.startswith('__')}
            if explicit:
                yield ea, explicit
            continue
        return

    @classmethod
    def contents(cls, *args):
        '''Query the contents of each function and yield a tuple containing its address and a set of the matching `required` tags with any `included` ones.'''
        if args:
            for pair in query_v0.contents(*args):
                yield pair
            return

        # No specific tags were selected, so just yield all tagnames that are
        # available while being sure to exclude the empty and any implicit tags.
        for ea, res in query_v0.contents(*args):
            explicit = {tag for tag in res if tag and not tag.startswith('__')}
            if explicit:
                yield ea, explicit
            continue
        return

    @classmethod
    def function(cls, func, *args):
        '''Query the contents of the function `func` and yield a tuple containing each address and all of the `required` tags with any `included` ones.'''
        if args:
            for pair in query_v0.function(func, *args):
                yield pair
            return

        # If nothing specific was selected, then yield all tags that are not the
        # empty tag or are an implicit tag that is dunder-prefixed.
        for ea, res in query_v0.function(func, *args):
            explicit = {tag : value for tag, value in res.items() if tag and not tag.startswith('__')}
            if explicit:
                yield ea, explicit
            continue
        return

    @classmethod
    def structures(cls, *args):
        '''Query the structures in the database and yield a tuple containing each structure and all of the `required` tags with any `included` ones.'''
        if args:
            for sid, res in query_v0.structures(*args):
                item = internal.structure.new(sid, 0)
                yield item, res
            return

        # If nothing specified to filter the tags, then we need to filter the
        # empty tag and any dunder-prefixed tags from our query. We also need to
        # convert the structure id into an `internal.structure.structure_t`.
        for sid, res in query_v0.structures(*args):
            explicit = {tag : value for tag, value in res.items() if tag and not tag.startswith('__')}
            if explicit:
                yield internal.structure.new(sid, 0), explicit
            continue
        return

    @classmethod
    def structure(cls, sid, *args):
        '''Query the members of the structure `sid` from the database and yield a tuple containing all the chosen tags.'''

        # If we were given a structure_t or members_t, then preserve them and
        # extract the sid so that we can return items with the same base offset.
        if isinstance(sid, internal.structure.structure_t):
            owner, sptr = sid, sid.ptr
        elif isinstance(sid, internal.structure.members_t):
            owner, sptr = sid.owner, sid.owner.ptr
        else:
            owner = internal.structure.new(sid, 0)
            sptr = owner.ptr

        # If we were given some args to use for selecting certain tags, then we
        # can just trust our query and only need to convert its member id
        # into one of our `internal.structure.member_t` types.
        if args:
            for mid, res in query_v0.structure(sptr.id, *args):
                mowner, mindex, mptr = internal.structure.members.by_identifier(sptr, mid)
                yield internal.structure.member_t(owner, mindex), res
            return

        # Otherwise we're being asked to yield everything but the empty tag and
        # any implicit tags. We also convert the member id into a `member_t`.
        for mid, res in query_v0.structure(sptr.id, *args):
            mowner, mindex, mptr = internal.structure.members.by_identifier(sptr, mid)
            explicit = {tag : value for tag, value in res.items() if tag and not tag.startswith('__')}
            if explicit:
                yield internal.structure.member_t(owner, mindex), explicit
            continue
        return

    @classmethod
    def owners(cls, *args):
        '''Query the members in the database and yield a tuple containing the owning structure and a set of the matching `required` tags with any `included` ones.'''
        cache = {}

        # If we were given some tags to select with, then we can just trust
        # whatever the query gives us whilst still yielding a `member_t`.
        if args:
            for sid, res in query_v0.owners(*args):
                owner = cache[sid] if sid in cache else cache.setdefault(sid, internal.structure.new(sid, 0))
                yield owner, res
            return

        # FIXME: we should be using something other than an offset of 0 if the
        #        structure belongs to a frame.

        # We weren't given any tags, meaning we are being asked to yield all of
        # them. So we filter out the empty tag and any implicit tags by default.
        for sid, res in query_v0.owners(*args):
            explicit = {tag for tag in res if tag and not tag.startswith('__')}
            if explicit:
                owner = cache[sid] if sid in cache else cache.setdefault(sid, internal.structure.new(sid, 0))
                yield owner, explicit
            continue
        return

    @classmethod
    def members(cls, *args):
        '''Query the members in the database and yield a tuple containing the member and all of the `required` tags with any `included` ones.'''
        cache = {}

        # If we were given some tags to select the members with, then we can
        # just return whatever the query gives us. We only need to convert the
        # member id to an actual member that can be returned.
        if args:
            for mid, res in query_v0.members(*args):
                mowner, mindex, mptr = internal.structure.members.by_identifier(None, mid)

                # FIXME: we should be detecting the frame base offset for the owner
                #        in case the structure is a frame belonging to a function.
                owner = cache[mowner.id] if mowner.id in cache else cache.setdefault(mowner.id, internal.structure.new(mowner.id, 0))
                if res:
                    yield owner.members[mindex], res
                continue
            return

        # If no tags were provided, then we're supposed to yield all of them.
        # Still, be filter out the empty tag along with any implicit ones.
        for mid, res in query_v0.members(*args):
            mowner, mindex, mptr = internal.structure.members.by_identifier(None, mid)

            # FIXME: we should be detecting the frame base offset for the owner
            #        in case the structure is a frame belonging to a function.
            explicit = {tag for tag in res if tag and not tag.startswith('__')}
            if explicit:
                owner = cache[mowner.id] if mowner.id in cache else cache.setdefault(mowner.id, internal.structure.new(mowner.id, 0))
                yield owner.members[mindex], explicit
            continue
        return

    @classmethod
    def blocks(cls, func, *args):
        '''Query the basic blocks of the func `func` and yield a tuple containing each block and all of the `required` tags with any `included` ones.'''
        if args:
            for bb, res in query_v0.blocks(func, *args):
                yield bb, res
            return

        # If we weren't asked to select anything specifically, then we yield
        # everything but the empty tag and any implicit tags.
        for bb, res in query_v0.blocks(func, *args):
            explicit = {tag : value for tag, value in res.items() if tag and not tag.startswith('__')}
            if explicit:
                yield bb, explicit
            continue
        return

class query_v1(object):
    """
    This namespace is an abstraction layer around the various types of indices
    provided by the `internal.tagindex` module. It is responsible for
    simplifying the interaction with the tag index and providing a clean
    interface for the `select` namespace defined aftwards. The parameters for
    the functions in this namespace directly correlate to the parameters of the
    `select namespace.

    Each function within this namespace takes 2 important parameters that are
    relevant for filtering the results returned from the tag index. The first
    parameter is named "required" and is used to specify the tags that must
    exist in order for the address or location to be returned. The second
    parameter is named "included" and is used to specify any other tags that
    should be included in the yielded result. If none of these parameters are
    specified, each function will return all locations that have some kind of
    tag applied to them.
    """

    @classmethod
    def mask(cls, names):
        '''Return an integer that can be used to test the existence of the specified tag `names`.'''
        wanted = {name for name in names} if isinstance(names, (internal.types.unordered, internal.types.dictionary)) else {names}
        available = {name for name in wanted if internal.tagindex.tags.has(name)}
        missing = wanted - available
        if missing and wanted:
            logging.warning(u"{:s}.mask({!s}) : Error due to {:d} wanted tag{:s} ({!s}) being unavailable out of the {:d} tag{:s} being requested.".format('.'.join([__name__, cls.__name__]), names, len(missing), '' if len(missing) == 1 else 's', ', '.join(map("{!r}".format, sorted(missing))), len(wanted), '' if len(wanted) == 1 else 's'))
        return internal.tagindex.tags.mask(available)

    @classmethod
    def tags(cls):
        '''Return all of the tag names used by the globals in the database.'''
        used = internal.tagindex.globals.usage()
        return internal.tagindex.tags.names(used)

    @classmethod
    def functiontags(cls, func):
        '''Return all of the tag names used by the contents of the function `func`.'''
        fn = interface.function.by(func)
        ea, _ = interface.range.unpack(fn)
        used = internal.tagindex.contents.usage(ea)
        return internal.tagindex.tags.names(used)

    @classmethod
    def globals(cls, require=frozenset(), include=frozenset()):
        '''Yield the address and tags from the globals that contain all the tags in `require` and including any from `include`.'''
        rmask, imask = (cls.mask(names) for names in [require, include])
        requested, selection = rmask | imask, require or include
        for ea, used in internal.tagindex.globals.iterate():
            if not(used):
                continue
            elif rmask and used & rmask != rmask:
                continue
            elif not(rmask) and imask and not(used & imask):
                continue
            elif selection and used & requested:
                yield ea, internal.tagindex.tags.names(used & requested)
            elif not selection and used:
                yield ea, internal.tagindex.tags.names(used)
            continue
        return

    @classmethod
    def contents(cls, require=frozenset(), include=frozenset()):
        '''Yield the function address and tags from the contents of each function containing all the tags in `require` and including any from `include`.'''
        rmask, imask = (cls.mask(names) for names in [require, include])
        requested, selection = rmask | imask, require or include
        for ea, used in internal.tagindex.contents.select():
            if not(used):
                continue
            elif rmask and used & rmask != rmask:
                continue
            elif not(rmask) and imask and not(used & imask):
                continue
            elif selection and used & requested:
                yield ea, internal.tagindex.tags.names(used & requested)
            elif not selection and used:
                yield ea, internal.tagindex.tags.names(used)
            continue
        return

    @classmethod
    def function(cls, func, require=frozenset(), include=frozenset()):
        '''Yield the contents address and tags from the contents of the function `func` containing all the tags in `require` and including any from `include`.'''
        fn = interface.function.by(func)
        rmask, imask = (cls.mask(names) for names in [require, include])
        requested, selection = rmask | imask, require or include
        for ea, used in internal.tagindex.contents.function(interface.range.start(fn)):
            if not(used):
                continue
            elif rmask and used & rmask != rmask:
                continue
            elif not(rmask) and imask and not(used & imask):
                continue
            elif selection and used & requested:
                yield ea, internal.tagindex.tags.names(used & requested)
            elif not selection and used:
                yield ea, internal.tagindex.tags.names(used)
            continue
        return

    @classmethod
    def structures(cls, require=frozenset(), include=frozenset()):
        '''Yield the structure id and tags from each structure containing all the tags in `require` and including any from `include`.'''
        rmask, imask = (cls.mask(names) for names in [require, include])
        requested, selection = rmask | imask, require or include
        for sid, used in internal.tagindex.structure.iterate():
            if not(used):
                continue
            elif rmask and used & rmask != rmask:
                continue
            elif not(rmask) and imask and not(used & imask):
                continue
            elif selection and used & requested:
                yield sid, internal.tagindex.tags.names(used & requested)
            elif not selection and used:
                yield sid, internal.tagindex.tags.names(used)
            continue
        return

    @classmethod
    def structure(cls, sid, require=frozenset(), include=frozenset()):
        '''Yield the member id and tags for each member belonging to the structure `sid` which contain all the tags in `require` and include any from `include`.'''
        struc_t = idaapi.struc_t, internal.structure.structure_t
        listable = sid if isinstance(sid, internal.types.ordered) else [sid]
        sids = {(sid.id if isinstance(sid, struc_t) else int(sid)) for sid in listable}
        rmask, imask = (cls.mask(names) for names in [require, include])
        requested, selection = rmask | imask, require or include
        for mid, used in internal.tagindex.members.structure(sids):
            if not(used):
                continue
            elif rmask and used & rmask != rmask:
                continue
            elif not(rmask) and imask and not(used & imask):
                continue
            elif selection and used & requested:
                yield mid, internal.tagindex.tags.names(used & requested)
            elif not selection and used:
                yield mid, internal.tagindex.tags.names(used)
            continue
        return

    @classmethod
    def owners(cls, require=frozenset(), include=frozenset()):
        '''Yield the owning structure id and tags for each structure with members that use all the tags in `require` and include any from `include`.'''
        rmask, imask = (cls.mask(names) for names in [require, include])
        requested, selection = rmask | imask, require or include
        for sid, used in internal.tagindex.members.select():
            if not(used):
                continue
            elif rmask and used & rmask != rmask:
                continue
            elif not(rmask) and imask and not(used & imask):
                continue
            elif selection and used & requested:
                yield sid, internal.tagindex.tags.names(used & requested)
            elif not selection and used:
                yield sid, internal.tagindex.tags.names(used)
            continue
        return

    @classmethod
    def members(cls, require=frozenset(), include=frozenset()):
        '''Yield the member id and tags for each member in the database using all the tags in `require` and including any from `include`.'''
        rmask, imask = (cls.mask(names) for names in [require, include])
        requested, selection = rmask | imask, require or include
        for mid, used in internal.tagindex.members.forward():
            if not(used):
                continue
            elif rmask and used & rmask != rmask:
                continue
            elif not(rmask) and imask and not(used & imask):
                continue
            elif selection and used & requested:
                yield mid, internal.tagindex.tags.names(used & requested)
            elif not selection and used:
                yield mid, internal.tagindex.tags.names(used)
            continue
        return

    @classmethod
    def blocks(cls, func, require=frozenset(), include=frozenset()):
        '''Yield the basic block and tags from the basib blocks of the function `func` containing all the tags in `require` and including any from `include`.'''
        flags = getattr(idaapi, 'FC_NOEXT', 2) | getattr(idaapi, 'FC_CALL_ENDS', 0x20)
        iterable = require if isinstance(require, (internal.types.unordered, internal.types.dictionary)) else {require}
        required = {key for key in iterable}
        iterable = include if isinstance(include, (internal.types.unordered, internal.types.dictionary)) else {include}
        included = {key for key in iterable}

        # First thing is to figure out which function we're supposed to query
        # for basic block tags.
        fn = interface.function.by(func)
        ea = interface.range.start(fn)

        # Enumerate all the basic blocks and build a map so that we can fetch
        # them by address. We also preserve the order that we received them so
        # that we can yield our results within the same order.
        blockmap = [(interface.range.start(bb), bb) for bb in interface.function.blocks(fn, flags)]
        order = [ea for ea, _ in blockmap]
        blocks = {ea : bb for ea, bb in blockmap}

        # Now we just need to union our tagged addresses with the ones which
        # are basic-blocks to get a list of the addresses actually selected.
        available = {ea for ea, _ in cls.function(fn)}
        selected = {ea for ea in available} & {ea for ea in order}
        ordered = [ea for ea in order if ea in selected]

        # If we weren't ask to query anything specific, then iterate using our
        # ordered blocks and yield anything that has tags associated with them.
        if not(required or included):
            for ea in ordered:
                res = block.get(blocks[ea])
                if res: yield blocks[ea], res
            return

        # Otherwise, walk through every matching address, and cross-check it
        # against the query that we were asked to make.
        # FIXME: we really should be using the tagindex here.
        for ea in ordered:
            res = block.get(blocks[ea])
            collected = {key : value for key, value in res.items() if key in included}

            # If we were given any tags that are required, add them to our
            # collection so that they can be yielded. If none of the required
            # tags exist, then continue onto the next basic block.
            if required:
                if required & {tag for tag in res} == required:
                    collected.update({key : value for key, value in res.items() if key in required})
                else: continue

            # If any tags were collected, then we can just yield them.
            if collected:
                yield blocks[ea], collected
            continue
        return

    @classmethod
    def blocks(cls, func, require=frozenset(), include=frozenset()):
        '''Yield the basic block and tags from the basic blocks of the function `func` containing all the tags in `require` and including any from `include`.'''
        flags = getattr(idaapi, 'FC_NOEXT', 2) | getattr(idaapi, 'FC_CALL_ENDS', 0x20)
        rmask, imask = (cls.mask(names) for names in [require, include])
        requested, selection = rmask | imask, require or include

        # Enumerate all the basic blocks and build a map so that we can fetch
        # them by address. We also preserve the order that we received them so
        # that we can yield our results within the same order.
        fn = interface.function.by(func)
        blockmap = [(interface.range.start(bb), bb) for bb in interface.function.blocks(fn, flags)]
        order = [ea for ea, _ in blockmap]
        blocks = {ea : bb for ea, bb in blockmap}
        ranges = {ea : interface.range.unpack(bb) for ea, bb in blockmap}

        # Now we just need to union our tagged addresses with the ones which
        # are basic-blocks to get a list of the addresses actually selected.
        available = {ea for ea, _ in cls.function(fn)}
        selected = {ea for ea in available} & {ea for ea in order}
        ordered = [ea for ea in order if ea in selected]

        # Otherwise, walk through every matching address, and cross-check it
        # against the query that we were asked to make.
        for ea in ordered:
            items = internal.tagindex.contents.range(*ranges[ea])
            iterable = (integer for ea, integer in items)
            used = functools.reduce(operator.or_, iterable, 0)
            if not(used):
                continue
            elif rmask and used & rmask != rmask:
                continue
            elif not(rmask) and imask and not(used & imask):
                continue
            elif selection and used & requested:
                yield blocks[ea], internal.tagindex.tags.names(used & requested)
            elif not selection and used:
                yield blocks[ea], internal.tagindex.tags.names(used)
            continue
        return

class select_v1(object):
    """
    This namespace is used to query different types of tags from the tagindex
    and yield the results to the caller. The information yielded to the caller
    is in the form of a tuple composed of the unique address or location of the
    tags, and then the tags themselves. The results of these functions can be
    used to create a dictionary by the caller if necessary.

    Filtering of the results from the functions in this namespace is done by
    specifying a group of "required" tags, which must exist for the location to
    be yielded, and/or a group of "included" tags which will be included in the
    yielded result if they are found. If no "required" or "included" tags are
    specified, then all of the results from the index will be yielded.
    """

    navigation = __import__('ui').navigation

    @classmethod
    def database(cls, *args):
        '''Query the globals in the database and yield a tuple containing its address and all of the `required` tags with any `included` ones.'''
        selection = True if any(args) else False
        for ea, used in query_v1.globals(*args):
            is_function = interface.function.has(cls.navigation.set(ea))
            Ftag = function.get if is_function else address.get
            tags, owners = Ftag(ea), {f for f in interface.function.owners(ea)} if is_function else {ea}
            selected = {key : value for key, value in tags.items() if key in used}
            if ea not in owners:
                continue
            yield ea, selected if selection else tags
        return

    @classmethod
    def contents(cls, *args):
        '''Query the contents of each function and yield a tuple containing its address and a set of the matching `required` tags with any `included` ones.'''
        selection = True if any(args) else False
        for ea, used in query_v1.contents(*args):
            is_function = interface.function.has(cls.navigation.procedure(ea))
            owners = {f for f in interface.function.owners(ea)} if is_function else {ea}
            if ea not in owners:
                continue
            yield ea, used
        return

    @classmethod
    def function(cls, func, *args):
        '''Query the contents of the function `func` and yield a tuple containing each address and all of the `required` tags with any `included` ones.'''
        selection = True if any(args) else False
        for ea, used in query_v1.function(func, *args):
            tags = address.get(cls.navigation.analyze(ea))
            selected = {key : value for key, value in tags.items() if key in used}
            yield ea, selected if selection else tags
        return

    @classmethod
    def structures(cls, *args):
        '''Query the structures in the database and yield a tuple containing each structure and all of the `required` tags with any `included` ones.'''
        selection = True if any(args) else False
        for sid, used in query_v1.structures(*args):
            tags = structure.get(sid)
            selected = {key : value for key, value in tags.items() if key in used}
            res = internal.structure.new(sid, 0)
            yield res, selected if selection else tags
        return

    @classmethod
    def owners(cls, *args):
        '''Query the members in the database and yield a tuple containing the owning structure for the member and a set of the matching `required` tags with any `included` ones.'''
        # FIXME: we should be using an offset other than 0 if the structure
        #        being yielded belongs to a frame.
        for sid, used in query_v1.owners(*args):
            yield internal.structure.new(sid, 0), used
        return

    @classmethod
    def members(cls, *args):
        '''Query the members in the database and yield a tuple containing the member and a set of the matching `required` tags with any `included` ones.'''
        cache = {}
        # FIXME: we should be using an offset other than 0 if the owner of the
        #        member being yielded is a frame for a function.
        for mid, used in query_v1.members(*args):
            mowner, mindex, mptr = internal.structure.members.by_identifier(None, mid)
            owner = cache[mowner.id] if mowner.id in cache else cache.setdefault(mowner.id, internal.structure.new(mowner.id, 0))
            yield owner.members[mindex], used
        return

    @classmethod
    def structure(cls, sid, *args):
        '''Query the members of the structure `sid` and yield a tuple containing each member and all of the `required` tags with any `included` ones.'''
        selection, cache = True if any(args) else False, {}
        for mid, used in query_v1.structure(sid, *args):
            tags = member.get(mid)
            selected = {key : value for key, value in tags.items() if key in used}
            sptr, mindex, mptr = internal.structure.members.by_identifier(None, mid)
            if sptr.id not in cache:
                mowner = cache.setdefault(sptr.id, internal.structure.new(sptr.id, 0))
            else:
                mowner = cache[sptr.id]
            yield mowner.members[mindex], selected if selection else tags
        return

    @classmethod
    def blocks(cls, func, *args):
        '''Query the basic blocks of the func `func` and yield a tuple containing each block and all of the `required` tags with any `included` ones.'''
        selection, cache = True if any(args) else False, {}
        for bb, used in query_v1.blocks(func, *args):
            tags = block.get(bb)
            selected = {key : value for key, value in tags.items() if key in used}
            yield bb, selected if selection else tags
        return

    @classmethod
    def blocks(cls, func, *args):
        '''Query the basic blocks of the func `func` and yield a tuple containing each block and all of the `required` tags with any `included` ones.'''
        return query_v1.blocks(func, *args)

# Select the namespace that uses the tagging cache by default.
query, select = query_v0, select_v0

class address(object):
    """
    This namespace is responsible for reading from and writing tags to
    an address. Each address can be either a global or associated with
    the contents of a function and supports the following implicit tags:

        `__name__` - The name for the address which is preserved if the name is mangled.
        `__color__` - The color of the item at the given address..
        `__extra_prefix__` - The anterior comment of the item at the given address.
        `__extra_suffix__` - The posterior comment of the item at the given address.
        `__typeinfo__` - Any type information that is associated with the address.

    The tags for each address are indexed and maintained using the `reference`
    namespace that can be found within this module.
    """

    @classmethod
    def get(cls, ea):
        '''Return a dictionary containing the tags for the item at address `ea`.'''
        MNG_NODEFINIT, MNG_NOPTRTYP = getattr(idaapi, 'MNG_NODEFINIT', 8), getattr(idaapi, 'MNG_NOPTRTYP', 7)

        ea = interface.address.inside(int(ea))

        # Check if we're within a function and determine whether it's a
        # runtime-linked address or not. If we're within a function, then
        # we need to ensure that we're using non-repeatable comments.
        try:
            func = interface.function.by_address(ea)
            rt, _ = interface.addressOfRuntimeOrStatic(ea if func is None else func)

        # If the address is not within a function, then assign some variables
        # so that we will use a repeatable comment.
        except LookupError:
            rt, func = False, None
        repeatable = False if func and interface.function.has(ea) and not rt else True

        # Read both repeatable and non-repeatable comments from the chosen
        # address so that we can decode both of them into dictionaries to
        # use. We also decode the (repeatable) function comment, because in
        # some cases a function is created for a runtime-linked address.
        d1 = comment.decode(utils.string.of(idaapi.get_cmt(ea, False) or ''))
        d2 = comment.decode(utils.string.of(idaapi.get_cmt(ea, True) or ''))
        d3 = comment.decode(utils.string.of(idaapi.get_func_cmt(func, True) or '') if rt else '')
        d1keys, d2keys, d3keys = ({key for key in item} for item in [d1, d2, d3])

        # Check if the address had content in either decoding types of
        # comments so that we can warn the user about it.
        if d1keys & d2keys:
            logging.info(u"{:s}.tag({:#x}) : Contents of both the repeatable and non-repeatable comment conflict with one another due to using the same keys ({:s}). Giving the {:s} comment priority.".format('database', ea, ', '.join(operator.and_(d1keys, d2keys)), 'repeatable' if repeatable else 'non-repeatable'))
        if rt and (operator.and_(d3keys, d1keys) or operator.and_(d3keys, d2keys)):
            logging.info(u"{:s}.tag({:#x}) : Contents of the runtime-linked comment conflict with one of the database comments due to using the same keys ({:s}). Giving the {:s} comment priority.".format('database', ea, ', '.join(operator.and_(d3keys, d2keys) or operator.and_(d3keys, d1keys)), 'function'))

        # Merge all of the decoded tags into a dictionary while giving priority
        # to the correct one. If the address was pointing to a runtime-linked
        # address and was a case that had a function comment, then we need to
        # give those tags absolute priority when building our dictionary.
        res = {}
        [res.update(d) for d in ([d1, d2] if repeatable else [d2, d1])]
        rt and res.update(d3)

        # First thing we need to figure out is whether the name exists and if
        # it's actually special in that we need to demangle it for the real name.
        aname = interface.name.get(ea)
        if aname and interface.name.mangled(ea, aname) != idaapi.FF_UNK:
            realname = utils.string.of(idaapi.demangle_name(utils.string.to(aname), MNG_NODEFINIT|MNG_NOPTRTYP) or aname)
        else:
            realname = aname or ''

        # Add any of the implicit tags for the specified address to our results.
        if aname and interface.address.flags(ea, idaapi.FF_NAME): res.setdefault('__name__', realname)
        if comment.extra.has_prefix(ea): res.setdefault('__extra_prefix__', comment.extra.get_prefix(ea))
        if comment.extra.has_suffix(ea): res.setdefault('__extra_suffix__', comment.extra.get_suffix(ea))

        # If there was some type information associated with the address, then
        # we need its name so that we can format it and add it as an implicit tag.
        try:
            if interface.address.has_typeinfo(ea):
                ti = interface.address.typeinfo(ea)

                # We need the name to be parseable and IDA just doesn't give a fuck if it outputs
                # something non-parseable. So we simply fix that here and render the typeinfo.
                validname = declaration.unmangled.parsable(realname)
                ti_s = idaapi.print_tinfo('', 0, 0, 0, ti, utils.string.to(validname), '')

                # Add it to our dictionary that we return to the user.
                res.setdefault('__typeinfo__', ti_s)

        # If we caught an exception, then the name from the type information could be
        # mangled and so we need to rip the type information directly out of the name.
        except internal.exceptions.InvalidTypeOrValueError:
            demangled = declaration.demangle(aname)

            # if the demangled name is different from the actual name, then we need
            # to extract its result type and prepend it to the demangled name.
            if demangled != aname:
                res.setdefault('__typeinfo__', demangled)

        # Add the implicit color to the result dictionary if one was actually set.
        col, DEFCOLOR = interface.address.color(ea), 0xffffffff
        if col != DEFCOLOR: res.setdefault('__color__', col)

        return res

    @classmethod
    def set(cls, ea, key, value):
        '''Set the tag specified by `key` to `value` for the item at address `ea`.'''
        if value is None:
            raise internal.exceptions.InvalidParameterError(u"{:s}.tag({:#x}, {!r}, {!r}) : Tried to set the tag (\"{:s}\") to an unsupported type {!r}.".format('database', ea, key, value, utils.string.escape(key, '"'), value))
        ea = interface.address.inside(int(ea))

        # If any of the supported implicit tags were specified, then figure out which
        # one and use it to choose the correct handler to use.
        if key == '__name__':
            local, filtered = interface.function.has(ea), interface.name.identifier(value)

            # If the name isn't used within the database, then we can just apply it...blindly.
            Fexists = functools.partial(interface.name.inside, ea) if local else interface.name.exists
            if not (interface.name.used(filtered) or Fexists(filtered)) or idaapi.get_name_ea(idaapi.BADADDR, filtered) == ea:
                return interface.name.set(ea, filtered) if local else interface.name.set(ea, filtered, 0, idaapi.SN_NOLIST)

            # Otherwise, we need an alternative name which we make by appending the offset.
            items, offset = [filtered], ea - interface.database.imagebase()
            while any(F(interface.tuplename(*items)) for F in [interface.name.used, Fexists]):
                items.append(offset)
            alternative = tuple(items)

            # Since we're changing the user's value, we need to figure out which warning
            # message to use by determining who owned the original name.
            address = idaapi.get_name_ea(ea if local else idaapi.BADADDR, filtered)
            target = internal.netnode.get(filtered) if address == idaapi.BADADDR else address
            description = "identifier {:#x}".format(target) if target == idaapi.BADADDR else "address {:#x}".format(target)
            logging.warning(u"{:s}.tag({:#x}, {!r}, {!r}) : Using an alternative name (\"{:s}\") for {:#x} due to {:s} {:#x} already being named \"{:s}\".".format('database', ea, key, value, utils.string.escape(interface.tuplename(*alternative), '"'), ea, 'identifier' if address == idaapi.BADADDR else 'address', target, utils.string.escape(filtered, '"')))

            # Now we can apply the damned name.
            return interface.name.set(ea, interface.tuplename(*alternative)) if local else interface.name.set(ea, interface.tuplename(*alternative), 0, idaapi.SN_NOLIST)

        elif key == '__extra_prefix__':
            return comment.extra.set_prefix(ea, value)

        elif key == '__extra_suffix__':
            return comment.extra.set_suffix(ea, value)

        elif key == '__color__':
            res, DEFCOLOR = interface.address.color(ea, value), 0xffffffff
            return None if res == DEFCOLOR else res

        elif key == '__typeinfo__':
            return cls.set_typeinfo(ea, value)

        # If we're within a function, then we also need to determine whether it's a
        # runtime-linked address or not. This is because if it's a runtime-linked
        # address then a repeatable comment is used. Otherwise we encode the tags
        # within a non-repeatable comment.
        try:
            func = interface.function.by(ea)
            rt, _ = interface.addressOfRuntimeOrStatic(ea if func is None else func)

        # If the address was not within a function, then set the necessary variables
        # so that a repeatable comment is used.
        except LookupError:
            rt, func = False, None

        # If we're outside a function or pointing to a runtime-linked address, then
        # we use a repeatable comment. Anything else means a non-repeatable comment.
        repeatable = False if func and interface.function.has(ea) and not rt else True

        # Go ahead and decode the tags that are written to all 3 comment types. This
        # way we can search them for the correct one that the user is trying to modify.
        state_correct = comment.decode(utils.string.of(idaapi.get_cmt(ea, repeatable)))
        state_wrong = comment.decode(utils.string.of(idaapi.get_cmt(ea, not repeatable)))
        state_runtime = comment.decode(utils.string.of(idaapi.get_func_cmt(func, True))) if func else {}

        # Now we just need to figure out which one of the dictionaries that we decoded
        # contains the key that the user is trying to modify. We need to specially
        # handle the case where the address is actually referring to a runtime address.
        if rt:
            rt, state, where = (True, state_runtime, True) if key in state_runtime else (False, state_wrong, False) if key in state_wrong else (True, state_runtime, True)
        else:
            state, where = (state_correct, repeatable) if key in state_correct else (state_wrong, not repeatable) if key in state_wrong else (state_correct, repeatable)

        # If the key was not in any of the encoded dictionaries, then we need to
        # update the reference count in the tag cache. If the address is a runtime
        # address or outside a function, then it's a global tag. Otherwise if it's
        # within a function, then it's a contents tag that we need to adjust.
        if key not in state:
            if func and interface.function.has(ea) and not rt:
                reference.contents.increment(ea, key)
            else:
                reference.globals.increment(ea, key)

        # Grab the previous value from the correct dictionary that we discovered,
        # and update it with the new value that the user is modifying it with.
        res, state[key] = state.get(key, None), value

        # Now we can finally update the comment in the database. However, we need
        # to guard the modification so that the hooks don't interfere with the
        # references that we updated. We guard this situation by disabling the hooks.
        import hook as hooker
        targets = {'changing_cmt', 'cmt_changed', 'changing_range_cmt', 'range_cmt_changed', 'changing_area_cmt', 'area_cmt_changed'} & {target for target in hooker.idb}
        try:
            [ hooker.idb.disable(item) for item in targets ]

        # If an exception was raised while disabling the hooks, then we need to bail.
        except Exception:
            raise

        # Finally we can actually encode the dictionary and write it to the address
        # the user specified using the correct comment type.
        else:
            idaapi.set_func_cmt(func, utils.string.to(comment.encode(state)), where) if rt else idaapi.set_cmt(ea, utils.string.to(comment.encode(state)), where)

        # Lastly we release the hooks now that we've finished modifying the comment.
        finally:
            [ hooker.idb.enable(item) for item in targets ]

        # Now we can return the result the user asked us for.
        return res

    @classmethod
    def clear_typeinfo(cls, ea, none):
        '''Remove the type information from the item at address `ea`.'''
        key = '__typeinfo__'
        if none is not None:
            raise internal.exceptions.InvalidParameterError(u"{:s}.tag({:#x}, {!r}, {!r}) : Tried to remove the type information from the given address with an unsupported type {!r}.".format('database', ea, key, none, none))

        try:
            rt, ea = interface.addressOfRuntimeOrStatic(ea)

        # If we hit an exception, then we're not a function and all
        # we need to do is to apply our tinfo_t to the address.
        except LookupError:
            result, ok = interface.address.typeinfo(ea), interface.address.apply_typeinfo(ea, none)
            if not ok:
                raise internal.exceptions.DisassemblerError(u"{:s}.tag({:#x}, {!r}, {!r}) : Unable to remove the type information from the given address ({:#x}).".format('database', ea, key, none, ea))
            return result

        # Otherwise we're being used on a function, and we need to do
        # the exact same thing but with the interface.function api.
        result, ok = interface.function.typeinfo(ea), interface.function.apply_typeinfo(ea, none)
        if not ok:
            raise internal.exceptions.DisassemblerError(u"{:s}.tag({:#x}, {!r}, {!r}) : Unable to remove the type information from the given function ({:#x}).".format('database', ea, key, none, ea))
        return result

    @classmethod
    def set_typeinfo(cls, ea, value, forced=False):
        '''Apply the type information specified by `value` to the item at address `ea`.'''
        info, key = interface.tinfo.parse(None, value, idaapi.PT_SIL) if isinstance(value, internal.types.string) else value, '__typeinfo__'
        if info is None:
            raise internal.exceptions.InvalidTypeOrValueError(u"{:s}.tag({:#x}, {!r}, {!r}) : Unable to parse the provided string ({!s}) into a type declaration.".format('database', ea, key, value, utils.string.repr(value), ea))

        try:
            rt, ea = interface.addressOfRuntimeOrStatic(ea)

        # If we hit an exception, then we're not a function and all
        # we need to do is to apply our tinfo_t to the address.
        except LookupError:
            result, ok = interface.address.typeinfo(ea), interface.address.apply_typeinfo(ea, info)
            if not ok:
                raise internal.exceptions.DisassemblerError(u"{:s}.tag({:#x}, {!r}, {!r}) : Unable to apply the given type ({!s}) to the address ({:#x}).".format('database', ea, key, value, utils.string.repr("{!s}".format(info)), ea))
            return result

        # Now we can apply the type to the address if it's runtime-linked.
        if rt:
            ti = info if forced else interface.function.pointer(info)

            # If we didn't get a type back, then we failed during promotion.
            if ti is None:
                raise internal.exceptions.DisassemblerError(u"{:s}.tag({:#x}, {!r}, {!r}) : Unable to promote type (\"{:s}\") to a pointer for the runtime-linked address ({:#x}).".format('database', ea, key, value, utils.string.repr("{!s}".format(ti)), ea))

            # Otherwise warn the user about the dirty thing we just did.
            elif ti is not info:
                logging.warning(u"{:s}.tag({:#x}, {!r}, {!r}) : Promoted the given type (\"{:s}\") to a pointer before applying it to the runtime-linked address ({:#x}).".format('database', ea, key, value, utils.string.repr("{!s}".format(ti)), ea))

            # Now we can just apply our tinfo_t to the address.
            result, ok = interface.function.typeinfo(ea), interface.function.apply_typeinfo(ea, ti)
            if not ok:
                raise internal.exceptions.DisassemblerError(u"{:s}.tag({:#x}, {!r}, {!r}) : Unable to apply the given type ({!s}) to runtime-linked address ({:#x}).".format('database', ea, key, value, utils.string.repr("{!s}".format(ti)), ea))
            return result

        # Otherwise, we're tagging a function and this is the wrong classmethod.
        return function.set_typeinfo(ea, info)

    @classmethod
    def remove(cls, ea, key, none):
        '''Remove the tag specified by `key` from the item at address `ea`.'''
        if none is not None:
            raise internal.exceptions.InvalidParameterError(u"{:s}.tag({:#x}, {!r}, {!r}) : Tried to set the tag (\"{:s}\") to an unsupported type {!r}.".format('database', ea, key, none, utils.string.escape(key, '"'), none))
        ea = interface.address.inside(int(ea))

        # If any of the supported implicit tags were specified, then dispatch to
        # the correct function in order to properly clear it.
        if key == '__name__':
            return interface.name.set(ea, none)
        elif key == '__extra_prefix__':
            return comment.extra.delete_prefix(ea)
        elif key == '__extra_suffix__':
            return comment.extra.delete_suffix(ea)
        elif key == '__typeinfo__':
            return cls.clear_typeinfo(ea, none)
        elif key == '__color__':
            DEFCOLOR = 0xffffffff
            res = interface.address.color(ea, DEFCOLOR)
            return None if res == DEFCOLOR else res

        # If we're within a function, then we need to distinguish whether the
        # address is a runtime-linked one or not. This way we can determine the
        # actual comment type that will be used.
        try:
            func = interface.function.by(ea)
            rt, _ = interface.addressOfRuntimeOrStatic(ea if func is None else func)

        # If the address wasn't within a function, then assign the necessary
        # values to the variables so that a repeatable comment gets used.
        except LookupError:
            rt, func = False, None

        # If we're outside a function or pointing to a runtime-linked address, then
        # a repeatable comment gets used. Inside a function is always a non-repeatable.
        repeatable = False if func and interface.function.has(ea) and not rt else True

        # figure out which comment type the user's key is in so that we can remove
        # that one. if we're a runtime-linked address, then we need to remove the
        # tag from a repeatable function comment. if the tag isn't in any of them,
        # then it doesn't really matter since we're going to raise an exception anyways.

        # Now we decode the tags from are written to all 3 available comment types.
        # This way we can search for the correct one that the user is going to modify.
        state_correct = comment.decode(utils.string.of(idaapi.get_cmt(ea, repeatable)))
        state_wrong = comment.decode(utils.string.of(idaapi.get_cmt(ea, not repeatable)))
        state_runtime = comment.decode(utils.string.of(idaapi.get_func_cmt(func, True))) if func else {}

        # Then we need to figure out which one of the decoded dictionaries contains
        # the key that the user is trying to remove. The case where a runtime-linked
        # address is being referenced needs to be specially handled as IDA may
        # incorrectly declare some runtime-linked addresses as functions.
        if rt:
            rt, state, where = (True, state_runtime, True) if key in state_runtime else (False, state_wrong, False) if key in state_wrong else (True, state_runtime, True)
        else:
            state, where = (state_correct, repeatable) if key in state_correct else (state_wrong, not repeatable) if key in state_wrong else (state_correct, repeatable)

        # If the key is not in the expected dictionary, then raise an exception. If
        # it is, then we can modify the dictionary and remove it to return to the user.
        if key not in state:
            raise internal.exceptions.MissingTagError(u"{:s}.tag({:#x}, {!r}, {!s}) : Unable to remove non-existent tag \"{:s}\" from address.".format('database', ea, key, none, utils.string.escape(key, '"')))
        res = state.pop(key)

        # Now we can do our update and encode our modified dictionary, but we need
        # to guard the modification so that the hooks don't also interfere with the
        # references that we're updating. We guard by disabling the relevant hooks.
        import hook as hooker
        targets = {'changing_cmt', 'cmt_changed', 'changing_range_cmt', 'range_cmt_changed', 'changing_area_cmt', 'area_cmt_changed'} & {target for target in hooker.idb}
        try:
            [ hooker.idb.disable(item) for item in targets ]

        # If an exception was raised while disabling the hooks, then simply bail.
        except Exception:
            raise

        # Finally we can encode the dictionary that we removed the key from and
        # write it to the correct comment at the address that the user specified.
        else:
            idaapi.set_func_cmt(func, utils.string.to(comment.encode(state)), where) if rt else idaapi.set_cmt(ea, utils.string.to(comment.encode(state)), where)

        # Release our hooks once we've finished updating the comment.
        finally:
            [ hooker.idb.enable(item) for item in targets ]

        # Now that we've removed the key from the tag and updated the comment,
        # we need to remove its reference. If the address is a runtime address
        # or outside a function, then it's a global tag being removed. Otherwise
        # it's within a function and thus a contents tag being removed.
        if func and interface.function.has(ea) and not rt:
            reference.contents.decrement(ea, key)
        else:
            reference.globals.decrement(ea, key)

        # Finally we can return the value of the tag that was removed.
        return res

class function(object):
    """
    This namespace is responsible for reading from and writing tags for
    a function. The tags belonging to a function are considered global
    tags that are distinctly separate from the function's contents. This
    type of tagging supports the following implicit tags:

        `__name__` - The name of the given function demangled if it is mangled.
        `__color__` - The color of the entire function.
        `__typeinfo__` - The type information of the function which contains its prototype.

    The tags for each individual function are indexed and maintained using
    the `internal.tags.reference.global` namespace (in this module).
    """

    @classmethod
    def get(cls, func):
        '''Return a dictionary containing the tags for the function `func`.'''
        MNG_NODEFINIT, MNG_NOPTRTYP, MNG_LONG_FORM = getattr(idaapi, 'MNG_NODEFINIT', 8), getattr(idaapi, 'MNG_NOPTRTYP', 7), getattr(idaapi, 'MNG_LONG_FORM', 0x6400007)

        try:
            rt, ea = interface.addressOfRuntimeOrStatic(func)

        # If the given location was not within a function, then fall back to a database tag.
        except internal.exceptions.FunctionNotFoundError:
            parameter = ("{:#x}" if isinstance(func, internal.types.integer) else "{!r}").format(func)
            logging.warning(u"{:s}.tag({:s}) : Attempted to read any tags from a non-function ({:s}). Falling back to using database tags.".format('function', parameter, parameter))
            return address.get(func)

        # If we were given a runtime function, then the address actually uses a database tag.
        if rt:
            logging.warning(u"{:s}.tag({:#x}) : Attempted to read any tags from a runtime-linked address ({:#x}). Falling back to using database tags.".format('function', ea, ea))
            return address.get(ea)

        # Read both repeatable and non-repeatable comments from the address, and
        # decode the tags that are stored within to a dictionary.
        fn, repeatable = interface.function.by_address(ea), True
        d1 = comment.decode(utils.string.of(idaapi.get_func_cmt(fn, False) or ''))
        d2 = comment.decode(utils.string.of(idaapi.get_func_cmt(fn, True) or ''))
        d1keys, d2keys = ({key for key in item} for item in [d1, d2])

        # Detect if the address had content in both repeatable or non-repeatable
        # comments so we can warn the user about what we're going to do.
        if d1keys & d2keys:
            logging.info(u"{:s}.tag({:#x}) : Contents of both the repeatable and non-repeatable comment conflict with one another due to using the same keys ({!r}). Giving the {:s} comment priority.".format('function', ea, ', '.join(d1keys & d2keys), 'repeatable' if repeatable else 'non-repeatable'))

        # Then we can store them into a dictionary whilst preserving priority.
        res = {}
        [ res.update(d) for d in ([d1, d2] if repeatable else [d2, d1]) ]

        # Collect all of the naming information for the function.
        fname, mangled = interface.function.name(ea), utils.string.of(idaapi.get_func_name(ea))
        if fname and interface.name.mangled(ea, mangled) != idaapi.FF_UNK:
            realname = utils.string.of(idaapi.demangle_name(utils.string.to(mangled), MNG_NODEFINIT|MNG_NOPTRTYP) or fname)
        else:
            realname = fname or ''

        # Add any of the implicit tags for the given function into our results.
        fname = fname
        if fname and interface.address.flags(interface.range.start(fn), idaapi.FF_NAME): res.setdefault('__name__', realname)

        # For the function's type information within the implicit "__typeinfo__"
        # tag, we'll need to extract the prototype and the function's name. This
        # is so that we can use the name to emit a proper function prototype.
        try:
            if interface.function.has_typeinfo(fn):
                ti = interface.function.typeinfo(fn)

                # We need this name to be parseable and (of course) IDA doesn't
                # give a fuck whether its output is parseable by its own parser.
                validname = declaration.unmangled.parsable(realname)
                fprototype = idaapi.print_tinfo('', 0, 0, 0, ti, utils.string.to(validname), '')
                res.setdefault('__typeinfo__', fprototype)

        # If an exception was raised, then we're using an older version of IDA and we
        # need to rip the type information from the unmangled name.
        except internal.exceptions.InvalidTypeOrValueError:
            None if fname == realname else res.setdefault('__typeinfo__', fname)

        # Add the color to the result if one was actually set.
        fcolor, DEFCOLOR = interface.function.color(fn), 0xffffffff
        if fcolor != DEFCOLOR: res.setdefault('__color__', fcolor)

        return res

    @classmethod
    def set(cls, func, key, value):
        '''Set the tag specified by `key` to `value` for the function `func`.'''
        if value is None:
            raise internal.exceptions.InvalidParameterError(u"{:s}.tag({:s}, {!r}, {!r}) : Tried to set the tag (\"{:s}\") to an unsupported type ({!s}).".format('function', ("{:#x}" if isinstance(func, internal.types.integer) else "{!r}").format(func), key, value, utils.string.escape(key, '"'), value))

        # Check to see if function tag is being applied to an import
        try:
            rt, ea = interface.addressOfRuntimeOrStatic(func)

        # If we're not even in a function, then use a database tag.
        except internal.exceptions.FunctionNotFoundError:
            logging.warning(u"{:s}.tag({:s}, {!r}, {!r}) : Attempted to set tag (\"{:s}\") for a non-function. Falling back to a database tag.".format('function', ("{:#x}" if isinstance(func, internal.types.integer) else "{!r}").format(func), key, value, utils.string.escape(key, '"')))
            return address.set(func, key, value)

        # If we are a runtime-only function, then write the tag to the import
        if rt:
            logging.warning(u"{:s}.tag({:#x}, {!r}, {!r}) : Attempted to set tag (\"{:s}\") for a runtime-linked symbol. Falling back to a database tag.".format('function', ea, key, value, utils.string.escape(key, '"')))
            return address.set(ea, key, value)

        # Otherwise, it's a function.
        fn = interface.function.by_address(ea)

        # If the user wants to modify any of the implicit tags, then we use the key
        # to figure out which function to dispatch to in order to modify it.
        if key == '__name__':
            filtered = interface.name.identifier(value)

            flag, preserved = idaapi.SN_NOWARN, idaapi.SN_NOWARN | idaapi.SN_NOLIST | idaapi.SN_PUBLIC|idaapi.SN_NON_PUBLIC | idaapi.SN_WEAK|idaapi.SN_NON_WEAK
            flag = 0 if idaapi.is_in_nlist(ea) else idaapi.SN_NOLIST
            flag = idaapi.SN_PUBLIC if idaapi.is_public_name(ea) else idaapi.SN_NON_PUBLIC
            flag = idaapi.SN_WEAK if idaapi.is_weak_name(ea) else idaapi.SN_NON_WEAK

            # If the name isn't used in the database, then just apply it.
            if not (interface.name.used(filtered) or interface.name.exists(filtered)) or idaapi.get_name_ea(idaapi.BADADDR, filtered) == ea:
                return interface.name.set(ea, filtered, flag, preserved)

            # Otherwise, we need an alternate name to avoid complaints.
            items, offset = [filtered], interface.range.start(fn) - interface.database.imagebase()
            while any(F(interface.tuplename(*items)) for F in [interface.name.used, interface.name.exists]):
                items.append(offset)
            alternative = tuple(items)

            # Since we're using a different name, we need to warn the user why.
            res = idaapi.get_name_ea(idaapi.BADADDR, filtered)
            target = internal.netnode.get(filtered) if res == idaapi.BADADDR else res
            description = "identifier {:#x}".format(target) if target == idaapi.BADADDR else "address {:#x}".format(target)
            logging.warning(u"{:s}.tag({:#x}, {!r}, {!r}) : Using an alternative name (\"{:s}\") for {:#x} due to {:s} {:#x} already being named \"{:s}\".".format('function', ea, key, value, utils.string.escape(interface.tuplename(*alternative), '"'), ea, 'identifier' if res == idaapi.BADADDR else 'address', target, utils.string.escape(filtered, '"')))

            # Now that the user knows what's up, we can apply the new name.
            return interface.name.set(ea, interface.tuplename(*alternative), flag, preserved)

        elif key == '__color__':
            res, DEFCOLOR = interface.function.color(fn, value), 0xffffffff
            return None if res == DEFCOLOR else res

        elif key == '__typeinfo__':
            return cls.set_typeinfo(fn, value)

        # Decode both comment types for the function so that we can figure out which
        # type that the tag they specified is currently in. If it's in neither, then
        # we can simply use a repeatable comment because we're a function.
        state_correct = comment.decode(utils.string.of(idaapi.get_func_cmt(fn, True))), True
        state_wrong = comment.decode(utils.string.of(idaapi.get_func_cmt(fn, False))), False
        state, where = state_correct if key in state_correct[0] else state_wrong if key in state_wrong[0] else state_correct

        # Grab the previous value from the correct dictionary, and update it with
        # the new value that was given to us.
        res, state[key] = state.get(key, None), value

        # Now we need to guard the modification of the comment so that we don't
        # mistakenly tamper with any of the reference counts in the tag cache.
        import hook as hooker
        targets = {'changing_range_cmt', 'range_cmt_changed', 'changing_area_cmt', 'area_cmt_changed'} & {target for target in hooker.idb}
        try:
            [ hooker.idb.disable(item) for item in targets ]

        # If we weren't able to disable the hooks due to an exception, then don't
        # bother to re-encoding the tags back into the comment.
        except Exception:
            raise

        # Finally we can encode the modified dict and write it to the function comment.
        else:
            idaapi.set_func_cmt(fn, utils.string.to(comment.encode(state)), where)

        # Release the hooks that we disabled since we finished modifying the comment.
        finally:
            [ hooker.idb.enable(item) for item in targets ]

        # If there wasn't a key in any of the dictionaries we decoded, then
        # we know one was added and so we need to update the tagging index.
        if res is None:
            reference.globals.increment(interface.range.start(fn), key)

        # return what we fetched from the dict
        return res

    @classmethod
    def set_typeinfo(cls, func, value):
        '''Apply the type information specified by `value` to the function `func`.'''
        rt, ea = interface.addressOfRuntimeOrStatic(func)

        # First we'll try and parse the type if it was given to us as a string.
        info, key = interface.tinfo.parse(None, value, idaapi.PT_SIL) if isinstance(value, internal.types.string) else value, '__typeinfo__'
        if info is None:
            raise internal.exceptions.InvalidTypeOrValueError(u"{:s}.tag({:#x}, {!r}, {!r}) : Unable to parse the provided string ({!s}) into a type declaration.".format('function', ea, key, value, utils.string.repr("{!s}".format(value)), ea))

        # If the type is not a function type whatsoever, then bail.
        if not any([info.is_func(), info.is_funcptr()]):
            raise internal.exceptions.InvalidTypeOrValueError(u"{:s}.tag({:#x}, {!r}, {!r}) : Refusing to apply a non-function type ({!r}) to the given {:s} ({:#x}).".format('function', ea, key, value, "{!s}".format(info), 'address' if rt else 'function', ea))

        # If we're being used against an export, then we need to make sure that
        # our type is a function pointer and we need to promote it if not.
        ti = interface.function.pointer(info)
        if rt and ti is None:
            raise internal.exceptions.DisassemblerError(u"{:s}.tag({:#x}, {!r}, {!r}) : Unable to promote type to a pointer due to being applied to a function pointer.".format('function', ea, key, value))

        elif ti is not info:
            logging.warning(u"{:s}.tag({:#x}, {!r}, {!r}) : Promoted type ({!r}) to a function pointer ({!r}) due to the address ({:#x}) being runtime-linked.".format('function', ea, key, value, "{!s}".format(info), "{!s}".format(ti), ea))

        # and then we just need to apply the type to the given address.
        result, ok = interface.function.typeinfo(ea), interface.function.apply_typeinfo(ea, ti)
        if not ok:
            raise internal.exceptions.DisassemblerError(u"{:s}.tag({:#x}, {!r}, {!r}) : Unable to apply typeinfo ({!r}) to the {:s} ({:#x}).".format('function', ea, key, value, "{!s}".format(ti), 'address' if rt else 'function', ea))
        return result

    @classmethod
    def clear_typeinfo(cls, func, none):
        '''Remove the type information from the function specified by `func`.'''
        key = '__typeinfo__'
        if none is not None:
            raise internal.exceptions.InvalidParameterError(u"{:s}.tag({:#x}, {!r}, {!r}) : Tried to remove the type information from the given function with an unsupported type {!r}.".format('function', ea, key, none, none))

        # Grab the address that we're supposed to clear and run with it.
        _, ea = interface.addressOfRuntimeOrStatic(func)
        result, ok = interface.function.typeinfo(ea), interface.function.apply_typeinfo(ea, none)
        if not ok:
            raise internal.exceptions.DisassemblerError(u"{:s}.tag({:#x}, {!r}, {!s}) : Unable to remove the type information from the given function ({:#x}).".format('function', ea, key, none, ea))
        return result

    @classmethod
    def remove(cls, func, key, none):
        '''Remove the tag specified by `key` from the function `func`.'''
        if none is not None:
            raise internal.exceptions.InvalidParameterError(u"{:s}.tag({:s}, {!r}, {!r}) : Tried to set the tag (\"{:s}\") to an unsupported type ({!s}).".format('function', ("{:#x}" if isinstance(func, types.integer) else "{!r}").format(func), key, none, utils.string.escape(key, '"'), none))

        # Check to see if function tag is being applied to an import
        try:
            rt, ea = interface.addressOfRuntimeOrStatic(func)

        # If we're not even in a function, then use a database tag.
        except internal.exceptions.FunctionNotFoundError:
            logging.warning(u"{:s}.tag({:s}, {!r}, {!s}) : Attempted to clear the tag for a non-function. Falling back to a database tag.".format('function', ('{:#x}' if isinstance(func, types.integer) else '{!r}').format(func), key, none))
            return address.remove(func, key, none)

        # If so, then write the tag to the import
        if rt:
            logging.warning(u"{:s}.tag({:#x}, {!r}, {!s}) : Attempted to set tag for a runtime-linked symbol. Falling back to a database tag.".format('function', ea, key, none))
            return address.remove(ea, key, none)

        # Otherwise, it's a function.
        fn = interface.function.by_address(ea)

        # If the user wants to remove any of the implicit tags, then we need to
        # dispatch to the correct function in order to clear the requested value.
        if key == '__name__':
            return name(fn, None)
        elif key == '__color__':
            DEFCOLOR = 0xffffffff
            res = interface.function.color(fn, DEFCOLOR)
            return None if res == DEFCOLOR else res
        elif key == '__typeinfo__':
            return cls.clear_typeinfo(func, none)

        # Decode both comment types so that we can figure out which comment type
        # the tag they're trying to remove is in. If it's in neither, then we just
        # assume which comment it should be in as an exception will be raised later.
        state_correct = comment.decode(utils.string.of(idaapi.get_func_cmt(fn, True))), True
        state_wrong = comment.decode(utils.string.of(idaapi.get_func_cmt(fn, False))), False
        state, where = state_correct if key in state_correct[0] else state_wrong if key in state_wrong[0] else state_correct

        # If the user's key was not in any of the decoded dictionaries, then raise
        # an exception because the key doesn't exist within the function's tags.
        if key not in state:
            raise internal.exceptions.MissingFunctionTagError(u"{:s}.tag({:#x}, {!r}, {!s}) : Unable to remove non-existent tag (\"{:s}\") from function.".format('function', ea, key, none, utils.string.escape(key, '"')))
        res = state.pop(key)

        # Before modifying the comment, we first need to guard its modification
        # so that the hooks don't also tamper with the reference count in the cache.
        import hook as hooker
        targets = {'changing_range_cmt', 'range_cmt_changed', 'changing_area_cmt', 'area_cmt_changed'} & {target for target in hooker.idb}
        try:
            [ hooker.idb.disable(item) for item in targets ]

        # If an exception was raised while trying to disable the hooks, then we just
        # give up and avoid re-encoding the user's tags back into the comment.
        except Exception:
            raise

        # Finally we can encode the modified dict back into the function comment.
        else:
            idaapi.set_func_cmt(fn, utils.string.to(comment.encode(state)), where)

        # Release the hooks that were disabled now that that comment has been written.
        finally:
            [ hooker.idb.enable(item) for item in targets ]

        # If we got here cleanly without an exception, then the tag was successfully
        # removed and we just need to update the tagging index with its removal.
        reference.globals.decrement(interface.range.start(fn), key)
        return res

class block(object):
    """
    This namespace is responsible for reading and writing any tags that are
    associated with a basic block from a function. A basic block is represented
    by the ``idaapi.BasicBlock`` that is fetched from an instance of the
    ``idaapi.FlowChart`` class for the desired function.

    The tags for a basic block can include the following implicit tags:

        `__color__` - The color of the basic block when displayed by the disassembler.

    The tags for a basic block are not indexed, and are instead grabbed from the
    function by iterating through the contents of the block.
    """

    @classmethod
    def get(cls, bb):
        '''Returns all the tags defined for the ``idaapi.BasicBlock`` given in `bb`.'''
        DEFCOLOR, ea = 0xffffffff, interface.range.start(bb)

        # first thing to do is to read the tags for the address. this
        # gives us "__extra_prefix__", "__extra_suffix__", and "__name__".
        res = address.get(ea)

        # next, we're going to replace the one implicit tag that we
        # need to handle...and that's the "__color__" tag.
        col = interface.function.blockcolor(bb)
        if col not in {None, DEFCOLOR}: res.setdefault('__color__', col)

        # that was pretty much it, so we can just return our results.
        return res

    @classmethod
    def set(cls, bb, key, value):
        '''Sets the value for the tag `key` to `value` in the ``idaapi.BasicBlock`` given by `bb`.'''
        DEFCOLOR, ea = 0xffffffff, interface.range.start(bb)

        # the only real implicit tag we need to handle is "__color__", because our
        # database.tag function does "__extra_prefix__", "__extra_suffix__", and "__name__".
        if key == '__color__':
            res = interface.function.blockcolor(bb, value)
            iterable = interface.address.items(*interface.range.unpack(bb))
            [ interface.address.color(ea, value) for ea in iterable ]
            return None if res == DEFCOLOR else res

        # now we can passthrough our key and value to the address namespace for
        # any of the explicit tags.
        return address.set(ea, key, value)

    @classmethod
    def remove(cls, bb, key, none):
        '''Removes the tag identified by `key` from the ``idaapi.BasicBlock`` given by `bb`.'''
        DEFCOLOR, ea = 0xffffffff, interface.range.start(bb)

        # if the '__color__' tag was specified, then explicitly clear it.
        if key == '__color__':
            res = interface.function.blockcolor(bb, DEFCOLOR)
            iterable = interface.address.items(*interface.range.unpack(bb))
            [ interface.address.color(ea, DEFCOLOR) for ea in iterable ]
            return None if res == DEFCOLOR else res

        # passthrough to the address namespace for removing whatever we don't
        # handle ourselves.
        return address.remove(ea, key, none)

class structure(object):
    """
    This namespace is responsible for the tags belonging to a structure,
    and provides functions for reading and writing to them. These tags
    are not generally queried, but are instead used for filtering a list
    of structures. The implicit tags that are available for a structure
    are instead used to expose certain characteristics about the definition
    of a structure. The implicit tags that are available are:

        `__name__` - The name of the structure, but only if it is listed by the structure list.
        `__typeinfo__` - The type for the structure, but only if the structure was explicitly created or modified by the user.

    The tags belonging to each structure are not indexed by the plugin.
    """

    @classmethod
    def get(cls, sptr):
        '''Return a dictionary containing the tags for the structure `sptr`.'''
        repeatable, sptr = True, idaapi.get_struc(int(sptr)) if isinstance(sptr, internal.types.integer) else sptr

        # grab the repeatable and non-repeatable comment for the structure
        d1 = comment.decode(internal.structure.comment.get(sptr, False))
        d2 = comment.decode(internal.structure.comment.get(sptr, True))
        d1keys, d2keys = ({key for key in item} for item in [d1, d2])

        # check for duplicate keys
        if d1keys & d2keys:
            logging.info(u"{:s}({:#x}).tag() : The repeatable and non-repeatable comment for structure {:s} use the same tags ({!r}). Giving priority to the {:s} comment.".format(cls.__name__, sptr.id, utils.string.repr(utils.string.of(idaapi.get_struc_name(sptr.id))), ', '.join(d1keys & d2keys), 'repeatable' if repeatable else 'non-repeatable'))

        # merge the dictionaries into one and return it (XXX: return a dictionary that automatically updates the comment when it's updated)
        res = {}
        [res.update(d) for d in ([d1, d2] if repeatable else [d2, d1])]

        # Now we need to add implicit tags which are related to the structure.

        # If we're a frame or we're unlisted, then we don't add the implicit
        # "__name__" tag. This way the user can select for "__name__" and use
        # it to distinguish local types and ghost types (which always have a name).
        excluded = ['SF_FRAME', 'SF_NOLIST']
        name = utils.string.of(idaapi.get_struc_name(sptr.id))
        if name and not any([sptr.props & getattr(idaapi, attribute) for attribute in excluded if hasattr(idaapi, attribute)]):
            res.setdefault('__name__', name)

        # Now we need to do the '__typeinfo__' tag. This is going to be a little
        # bit different than how we usually determine it, because we're going to
        # use it to determine whether the user created this type themselves or it
        # was created automatically. So, if it was copied from the type library
        # (SF_TYPLIB), from the local types (SF_GHOST), or the user chose not to
        # list it (SF_NOLIST), then we don't assign '__typeinfo__'.
        excluded = ['SF_FRAME', 'SF_GHOST', 'SF_TYPLIB', 'SF_NOLIST']
        if any([sptr.props & getattr(idaapi, attribute) for attribute in excluded if hasattr(idaapi, attribute)]):
            pass

        # SF_NOLIST is justified because if the user didn't want the structure to
        # be listed, then we're just doing as we're told. Everything else should
        # be justifiable because if the user did anything with the type, then
        # the other flags should've been cleared.
        else:
            ti = interface.address.typeinfo(sptr.id)
            ti_s = idaapi.print_tinfo('', 0, 0, 0, ti, '', '')
            res.setdefault('__typeinfo__', ti_s)
        return res

    @classmethod
    def set(cls, sptr, key, value):
        '''Set the tag specified by `key` to `value` for the structure `sptr`.'''
        if value is None:
            raise internal.exceptions.InvalidParameterError(u"{:s}({:#x}).tag({!r}, {!r}) : Tried to set the tag named \"{:s}\" with an unsupported type {!r}.".format(cls.__name__, sptr.id, key, value, utils.string.escape(key, '"'), value))

        # All structure tags are prioritized within repeatable comments.
        repeatable = True

        # First we need to read both comments to figure out what the user is trying to say.
        comment_right = internal.structure.comment.get(sptr, repeatable)
        comment_wrong = internal.structure.comment.get(sptr, not repeatable)

        # Decode the tags that are written to both comment types to figure out which
        # comment type the user actually means. The logic here reads weird because the
        # "repeatable" variable toggles which comment to give priority. We explicitly
        # check the "wrong" place but fall back to the "right" one.
        state_right, state_wrong = map(comment.decode, [comment_right, comment_wrong])
        state, where = (state_right, repeatable) if key in state_right else (state_wrong, not repeatable) if key in state_wrong else (state_right, repeatable)

        # If there were any duplicate keys in any of the dicts, then warn the user about it.
        duplicates = {item for item in state_right} & {item for item in state_wrong}
        if key in duplicates:
            sometimes_name = utils.string.of(idaapi.get_struc_name(sptr.id))
            logging.warning(u"{:s}({:#x}).tag({!r}, {!r}) : The repeatable and non-repeatable comment for structure {:s} use the same tags ({!r}). Giving priority to the {:s} comment.".format(cls.__name__, sptr.id, key, value, "{:#x}".format(sptr.id) if sometimes_name is None else utils.string.repr(sometimes_name), ', '.join(duplicates), 'repeatable' if where else 'non-repeatable'))

        # Now we can just update the dict and re-encode to the proper comment location.
        res, state[key] = state.get(key, None), value
        try:
            old = internal.structure.comment.set(sptr, comment.encode(state), where)

        except internal.exceptions.DisassemblerError:
            sometimes_name = utils.string.of(idaapi.get_struc_name(sptr.id))
            raise internal.exceptions.DisassemblerError(u"{:s}({:#x}).tag({!r}, {!r}) : Unable to update the {:s} comment for the structure {:s}.".format(cls.__name__, sptr.id, key, value, 'repeatable' if where else 'non-repeatable', "{:#x}".format(sptr.id) if sometimes_name is None else utils.string.repr(sometimes_name)))
        return res

    @classmethod
    def remove(cls, sptr, key, none):
        '''Remove the tag specified by `key` from the structure `sptr`.'''
        if none is not None:
            raise internal.exceptions.InvalidParameterError(u"{:s}({:#x}).tag({!r}, {!r}) : Tried to set the tag named \"{:s}\" with an unsupported type {!r}.".format(cls.__name__, sptr.id, key, none, utils.string.escape(key, '"'), value))

        # We prioritize the repeatable comments for tags belonging to structures.
        repeatable = True

        # First we check if the key is one of the implicit tags that we support. These
        # aren't we can modify since they only exist in special circumstances.
        if key in {'__name__', '__typeinfo__'} and key in cls.get(sptr):
            message_typeinfo = 'modified by the user from the default type library'
            message_name = 'flagged as listed by the user'

            # The characteristics aren't actually documented anywhere, so we'll raise an
            # exception that attempts to describe what causes them to exist. Hopefully
            # the user figures out that they can use them to find structures they created.
            message = message_typeinfo if key == '__typeinfo__' else message_name
            raise internal.exceptions.InvalidParameterError(u"{:s}({:#x}).tag({!r}, {!r}) : Unable to remove the implicit tag \"{:s}\" due to the structure being {:s}.".format(cls.__name__, sptr.id, key, none, utils.string.escape(key, '"'), message))

        # We need to read both comments to figure out where the tag is that we're trying to remove.
        comment_right = internal.structure.comment.get(sptr, repeatable)
        comment_wrong = internal.structure.comment.get(sptr, not repeatable)

        # Decode the tags that are written to both comment types, and then test them
        # to figure out which comment the key is encoded in. In this, we want
        # "repeatable" to be a toggle and we want to default to the selected comment.
        state_right, state_wrong = map(comment.decode, [comment_right, comment_wrong])
        state, where = (state_right, repeatable) if key in state_right else (state_wrong, not repeatable) if key in state_wrong else (state_right, repeatable)

        # If the key isn't where we expect it, then raise an exception since we can't
        # remove it if it doesn't actually exist.
        if key not in state:
            sometimes_name = utils.string.of(idaapi.get_struc_name(sptr.id))
            raise internal.exceptions.MissingTagError(u"{:s}({:#x}).tag({!r}, {!r}) : Unable to remove non-existing tag \"{:s}\" from the structure {:s}.".format(cls.__name__, sptr.id, key, none, utils.string.escape(key, '"'), "{:#x}".format(sptr.id) if sometimes_name is None else utils.string.repr(sometimes_name)))

        # If the key is in both dictionaries, then be kind and warn the user about it
        # so that they'll know that their key will still be part of the dict.
        duplicates = {item for item in state_right} & {item for item in state_wrong}
        if key in duplicates:
            sometimes_name = utils.string.of(idaapi.get_struc_name(sptr.id))
            logging.warning(u"{:s}({:#x}).tag({!r}, {!r}) : The repeatable and non-repeatable comment for structure {:s} use the same tags ({!r}). Giving priority to the {:s} comment.".format(cls.__name__, sptr.id, key, none, "{:#x}".format(sptr.id) if sometimes_name is None else utils.string.repr(sometimes_name), ', '.join(duplicates), 'repeatable' if where else 'non-repeatable'))

        # Now we can just pop the value out of the dict and re-encode back into the comment.
        res = state.pop(key)
        try:
            old = internal.structure.comment.set(sptr, comment.encode(state), where)

        except internal.exceptions.DisassemblerError:
            sometimes_name = utils.string.of(idaapi.get_struc_name(sptr.id))
            raise internal.exceptions.DisassemblerError(u"{:s}({:#x}).tag({!r}, {!r}) : Unable to update the {:s} comment for the structure {:s}.".format(cls.__name__, sptr.id, key, none, 'repeatable' if repeatable else 'non-repeatable', "{:#x}".format(sptr.id) if sometimes_name is None else utils.string.repr(sometimes_name)))
        return res

class member(object):
    """
    This namespace is responsible for the tags belonging to a member
    within a structure.  Similar to a structure, the structure member
    provides implicit tags that are used to expose specific characteristics
    of the member to the user. These implicit tags are as follows:

        `__name__` - The name of the member, but only if the name is not the default.
        `__typeinfo__` - The type information for the member if it exists.

    The tags belonging to each structure member are not indexed by the plugin.
    """

    @classmethod
    def get(cls, mptr):
        '''Return a dictionary containing the tags for the structure member `mptr`.'''
        repeatable, mid = True, mptr.id if isinstance(mptr, (idaapi.member_t, internal.structure.member_t)) else int(mptr)
        mptr, fullname, sptr = idaapi.get_member_by_id(mid)

        # Grab the repeatable and non-repeatable comment.
        d1 = comment.decode(utils.string.of(idaapi.get_member_cmt(mptr.id, False)))
        d2 = comment.decode(utils.string.of(idaapi.get_member_cmt(mptr.id, True)))
        d1keys, d2keys = ({key for key in item} for item in [d1, d2])

        # Check if decoding from both comments results in duplicate keys.
        if d1keys & d2keys:
            logging.info(u"{:s}({:#x}).tag() : The repeatable and non-repeatable comment for {:s} use the same tags ({!r}). Giving priority to the {:s} comment.".format(cls.__name__, mptr.id, utils.string.repr(utils.string.of(idaapi.get_member_fullname(mptr.id))), ', '.join(d1keys & d2keys), 'repeatable' if repeatable else 'non-repeatable'))

        # Merge the dictionaries into one before adding implicit tags.
        res = {}
        [res.update(d) for d in ([d1, d2] if repeatable else [d2, d1])]

        # Now we need to extract the name for two things. One of them is to detect if
        # the name is not a default, and the other is to include it in the rendered type.
        idaname = idaapi.get_member_name(mptr.id) or ''
        name = utils.string.of(idaname)

        # If the name is defined with something other than the default, then its a tag.
        aname = name if internal.structure.member.has_name(mptr) else ''
        if aname:
            res.setdefault('__name__', aname)

        # The next tag is the type information that we'll need to explicitly check for
        # because IDA will always figure it out and only want to include it iff the
        # user has created the type through some explicit action.

        # FIXME: We really should be tracking the application of types using a
        #        hook. Checking the flags like we are trying to do will likely
        #        fail on later versions of the disassembler.

        # If we belong to a frame, then we can trust the MF_HASTI property. We
        # can also use NSUP_TYPEINFO(0x3000) to confirm that type information of
        # some sort was applied. Although, it's not really that unnecessary.
        if sptr.props & getattr(idaapi, 'SF_FRAME', 0x40):
            ti, has_typeinfo = idaapi.tinfo_t(), mptr.flag & idaapi.MF_HASTI
            ok = idaapi.get_or_guess_member_tinfo2(mptr, ti) if idaapi.__version__ < 7.0 else idaapi.get_or_guess_member_tinfo(ti, mptr)

        # Otherwise we need to do something different since structures defined
        # by the user will _always_ be considered user-defined types and the
        # MF_HASTI property will _always_ be set for them. So, to come up with
        # some temporary way to accomplish this (without tracking it with a
        # hook), we identify a type as being user specified by distinguishing
        # whether it's a compiler type or an explicit one.
        else:
            ti = idaapi.tinfo_t()
            ok = idaapi.get_or_guess_member_tinfo2(mptr, ti) if idaapi.__version__ < 7.0 else idaapi.get_or_guess_member_tinfo(ti, mptr)
            has_typeinfo = ok and not interface.tinfo.basic(ti)

        # Now we need to attach the member name to our type so that it can
        # be rendered. Hopefully it's not mangled in some way that will need
        # consideration if it's reapplied by the user.
        if ok and has_typeinfo:
            ti_s = idaapi.print_tinfo('', 0, 0, 0, ti, utils.string.to(declaration.unmangled.parsable(aname) if aname else ''), '')
            res.setdefault('__typeinfo__', ti_s)
        return res

    @classmethod
    def set(cls, mptr, key, value):
        '''Set the tag specified by `key` to `value` for the structure member `mptr`.'''
        repeatable = True

        # Guard against a bunk type being used to set the value.
        if value is None:
            raise internal.exceptions.InvalidParameterError(u"{:s}({:#x}).tag({!r}, {!r}) : Tried to set the tag named \"{:s}\" with an unsupported type {!r}.".format(cls.__name__, mptr.id, key, value, utils.string.escape(key, '"'), value))

        # Before we do absolutely anything, we need to check if the user is updating
        # one of the implicit tags and act on them by assigning their new value.
        if key == '__name__':
            tags, original = cls.get(mptr), internal.structure.member.set_name(mptr, value)
            return tags.pop(key, None)

        elif key == '__typeinfo__':
            tags, original = cls.get(mptr), internal.structure.member.set_typeinfo(mptr, value)
            return tags.pop(key, None)

        # We need to grab both types of comments so that we can figure out
        # where the one that we're modifying is going to be located at.
        comment_right = utils.string.of(idaapi.get_member_cmt(mptr.id, repeatable))
        comment_wrong = utils.string.of(idaapi.get_member_cmt(mptr.id, not repeatable))

        # Now we'll decode both comments and figure out which one contains the key
        # that the user is attempting to modify. The "repeatable" variable is used
        # to toggle which comment gets priority which modifying the member's tags.
        state_right, state_wrong = map(comment.decode, [comment_right, comment_wrong])
        state, where = (state_right, repeatable) if key in state_right else (state_wrong, not repeatable) if key in state_wrong else (state_right, repeatable)

        # Check if the key is a dupe so that we can warn the user about it.
        duplicates = {item for item in state_right} & {item for item in state_wrong}
        if key in duplicates:
            logging.warning(u"{:s}({:#x}).tag({!r}, {!r}) : The repeatable and non-repeatable comment for member {:s} use the same tags ({!r}). Giving priority to the {:s} comment.".format('.'.join([__name__, cls.__name__]), mptr.id, key, value, utils.string.repr(utils.string.of(idaapi.get_member_fullname(mptr.id))), ', '.join(duplicates), 'repeatable' if where else 'non-repeatable'))

        # Now we just need to modify the state with the new value and re-encode it.
        res, state[key] = state.get(key, None), value
        if not idaapi.set_member_cmt(mptr, utils.string.to(comment.encode(state)), where):
            raise internal.exceptions.DisassemblerError(u"{:s}({:#x}).tag({!r}, {!r}) : Unable to update the {:s} comment for the member {:s}.".format('.'.join([__name__, cls.__name__]), mptr.id, key, value, 'repeatable' if where else 'non-repeatable', utils.string.repr(utils.string.of(idaapi.get_member_fullname(mptr.id)))))
        return res

    @classmethod
    def remove(cls, mptr, key, none):
        '''Remove the tag specified by `key` from the structure member `mptr`.'''
        if none is not None:
            raise internal.exceptions.InvalidParameterError(u"{:s}.tag({:#x}, {!r}, {!r}) : Tried to set the tag (\"{:s}\") to an unsupported type {!r}.".format('database', ea, key, none, utils.string.escape(key, '"'), none))
        repeatable = True

        # Check if the key is an implicit tag that we're being asked to
        # remove so that we can remove it from whatever it represents.
        if key == '__name__':
            tags, original = cls.get(mptr), internal.structure.member.remove_name(mptr)
            return tags.pop(key, None)

        elif key == '__typeinfo__':
            tags, original = cls.get(mptr), internal.structure.member.remote_typeinfo(mptr)
            return tags.pop(key, None)

        # Read both the comment types to figure out where the tag we want to remove is located at.
        comment_right = utils.string.of(idaapi.get_member_cmt(mptr.id, repeatable))
        comment_wrong = utils.string.of(idaapi.get_member_cmt(mptr.id, not repeatable))

        # Now we need to decode them and figure out which comment the tag we need
        # to remove is located in. This reads weird because "repeatable" is intended
        # to toggle which comment type we give priority to during removal.
        state_right, state_wrong = map(comment.decode, [comment_right, comment_wrong])
        state, where = (state_right, repeatable) if key in state_right else (state_wrong, not repeatable) if key in state_wrong else (state_right, repeatable)

        # If the key is not in the dictionary that we determined, then it's missing
        # and so we need to bail with an exception since it doesn't exist.
        if key not in state:
            raise internal.exceptions.MissingTagError(u"{:s}({:#x}).tag({!r}, {!r}) : Unable to remove non-existing tag \"{:s}\" from the member {:s}.".format('.'.join([__name__, cls.__name__]), mptr.id, key, none, utils.string.escape(key, '"'), utils.string.repr(utils.string.of(idaapi.get_member_fullname(mptr.id)))))

        # If there's any duplicate keys and the user's key is one of them, then warn
        # the user about it so they'll know that they'll need to remove it twice.
        duplicates = {item for item in state_right} & {item for item in state_wrong}
        if key in duplicates:
            logging.warning(u"{:s}({:#x}).tag({!r}, {!r}) : The repeatable and non-repeatable comment for member {:s} use the same tags ({!r}). Giving priority to the {:s} comment.".format('.'.join([__name__, cls.__name__]), mptr.id, key, none, utils.string.repr(utils.string.of(idaapi.get_member_fullname(mptr.id))), ', '.join(duplicates), 'repeatable' if where else 'non-repeatable'))

        # The very last thing to do is to remove the key from the dictionary
        # and then encode our updated state into the member's comment.
        res = state.pop(key)
        if not idaapi.set_member_cmt(mptr, utils.string.to(comment.encode(state)), where):
            raise internal.exceptions.DisassemblerError(u"{:s}({:#x}).tag({!r}, {!r}) : Unable to update the {:s} comment for the member {:s}.".format('.'.join([__name__, cls.__name__]), mptr.id, key, none, 'repeatable' if repeatable else 'non-repeatable', utils.string.repr(utils.string.of(idaapi.get_member_fullname(mptr.id)))))
        return res

class reference_v0(object):
    """
    This namespace is a frontend to the tagging backend that resides within the
    `internal.tagcache` module. The purpose of this is to simplify the interface
    that is used for accessing the tagcache. The implementation abstracts around
    global addresses, which include function entrypoints and addresses, that do
    not belong to a function. It also abstracts around content addresses which
    are associated with the contents of a function.

    There are also placeholder namespaces for accessing cached information about
    structures, unions, and their members. The implementation of the tagcache
    does not support applying tags to these types, so the implementation returns
    empty results for each of them.
    """

    class tags(object):
        """
        Basically a frontend to all of the tags used in the database.
        """
        @classmethod
        def has(cls, name):
            return name in internal.tagcache.globals.name()
        @classmethod
        def get(cls, name):
            iterable = (count for tag, count in internal.tagcache.globals.counts() if tag == name)
            return next(iterable, 0)
        @classmethod
        def name(cls):
            return internal.tagcache.globals.name()
        @classmethod
        def counts(cls):
            return {tag : count for tag, count in internal.tagcache.globals.counts()}

    class globals(object):
        """
        Basically a frontend to the addresses in a database that do not belong
        to a function.
        """
        @classmethod
        def get(cls, ea):
            res = function.get(ea) if interface.function.has(ea) else address.get(ea)
            return {tag for tag in res}
        @classmethod
        def has(cls, ea):
            res = function.get(ea) if interface.function.has(ea) else address.get(ea)
            return True if res else False
        @classmethod
        def increment(cls, address, name):
            return internal.tagcache.globals.inc(address, name)
        @classmethod
        def decrement(cls, address, name):
            return internal.tagcache.globals.dec(address, name)
        @classmethod
        def name(cls):
            return internal.tagcache.globals.name()
        @classmethod
        def address(cls):
            return internal.tagcache.globals.address()
        @classmethod
        def iterate(cls):
            return internal.tagcache.globals.iterate()
        @classmethod
        def counts(cls):
            return {tag : count for tag, count in internal.tagcache.globals.counts()}
        @classmethod
        def erase_address(cls, ea):
            start, stop = interface.address.bounds()
            if start <= ea < stop and any(idaapi.get_cmt(ea, repeatable) for repeatable in [True, False]):
                return internal.tagcache.globals.erase(ea)
            return internal.tagcache.globals.destroy(ea)

    class contents(object):
        """
        Basically a frontend to the addresses in a database belonging to a
        function.
        """
        @classmethod
        def has(cls, ea, **target):
            res = address.get(ea)
            return True if res else False
        @classmethod
        def get(cls, ea, **target):
            res = address.get(ea)
            return {tag for tag in res}
        @classmethod
        def increment(cls, address, name, **target):
            return internal.tagcache.contents.inc(address, name, target=target.get('target'))
        @classmethod
        def decrement(cls, address, name, **target):
            return internal.tagcache.contents.dec(address, name, target=target.get('target'))
        @classmethod
        def iterate(cls):
            return internal.tagcache.contents.iterate()
        @classmethod
        def name(cls, address, **target):
            return internal.tagcache.contents.name(address, target=target.get('target'))
        @classmethod
        def address(cls, address, **target):
            return internal.tagcache.contents.address(address, target=target.get('target'))
        @classmethod
        def counts(cls, address):
            iterable = internal.tagcache.contents.counts(address)
            return {tag : count for tag, count in iterable}
        @classmethod
        def erase_address(cls, func, ea):
            return internal.tagcache.contents.erase_address(func, ea)
        @classmethod
        def erase(cls, func):
            return internal.tagcache.contents.erase(func)

    class structure(object):
        """
        Basically a frontend for the structures in a database. There is no
        implementation because the `internal.tagcache` backend does not have
        support for structures or members.
        """
        @classmethod
        def has(cls, sid):
            res = structure.get(ea)
            return True if res else False
        @classmethod
        def get(cls, sid):
            res = structure.get(ea)
            return {tag for tag in res}
        @classmethod
        def increment(cls, sid, name):
            return 0
        @classmethod
        def decrement(cls, sid, name):
            return 0
        @classmethod
        def erase(cls, sid):
            return []

    class members(object):
        """
        Basically a frontend for the members from all the structures in the
        database. This has no implementation because the `internal.tagcache`
        backend does not have support for counting structures or members.
        """
        @classmethod
        def has(cls, mid):
            res = member.get(mid)
            return True if res else False
        @classmethod
        def get(cls, mid):
            res = member.get(mid)
            return {tag for tag in res}
        @classmethod
        def increment(cls, mid, name):
            return 0
        @classmethod
        def decrement(cls, mid, name):
            return 0
        @classmethod
        def erase_member(cls, sid, mid):
            return []
        @classmethod
        def erase(cls, sid):
            return []

class reference_v1(object):
    """
    This namespace is basically a frontend to whatever backend is currently
    selected. It is basically an abstraction around the entirety of the tagging
    index implemented by the `internal.tagindex` module. This includes global or
    function addresses, addresses belonging to the contents of a function,
    structures or unions, and the members for said structures or unions.
    """

    class tags(object):
        """
        Basically a frontend for all of the tags used in the database. It is
        primarily used to access global information about the tags, and is not
        really too useful.
        """
        @classmethod
        def has(cls, name):
            return internal.tagindex.tags.has(name)
        @classmethod
        def get(cls, name):
            position, count = internal.tagindex.tags.get(name)
            return count
        @classmethod
        def name(cls):
            used = internal.tagindex.tags.usage()
            return internal.tagindex.tags.names(used)
        @classmethod
        def counts(cls):
            iterable = internal.tagindex.tags.counts()
            return {name : count for name, count in iterable}

    class globals(object):
        """
        This namespace is a frontend for the addresses and functions inside a
        database. Addresses belonging to a function, but excluding the function
        entrypoint are excluded.
        """
        @classmethod
        def get(cls, ea):
            return internal.tagindex.globals.get(ea)
        @classmethod
        def has(cls, ea):
            res = internal.tagindex.globals.get(ea)
            return True if res else False
        @classmethod
        def increment(cls, address, name):
            position, count = internal.tagindex.globals.increment(address, name)
            return count
        @classmethod
        def decrement(cls, address, name):
            position, count = internal.tagindex.globals.decrement(address, name) if internal.tagindex.tags.has(name) else (0, 0)
            return count
        @classmethod
        def name(cls):
            used = internal.tagindex.globals.usage()
            return internal.tagindex.tags.names(used)
        @classmethod
        def address(cls):
            iterable = (ea for ea, _ in internal.tagindex.globals.forward())
            return iterable
        @classmethod
        def iterate(cls):
            iterable = ((ea, used) for ea, used in internal.tagindex.globals.forward())
            return ((ea, len(internal.tagindex.tags.names(used))) for ea, used in iterable)
        @classmethod
        def counts(cls):
            res, used = {}, (integer for ea, integer in internal.tagindex.globals.forward())
            for name in itertools.chain(*map(internal.tagindex.tags.names, used)):
                res[name] = res.setdefault(name, 0) + 1
            return res
        @classmethod
        def erase_address(cls, ea):
            count = internal.tagindex.globals.erase(ea)
            return count

    class contents(object):
        """
        This namespace is just a frontend for the addresses that belong to a
        function. Each address associated with a function is considered a
        "contents" address.
        """
        @classmethod
        def has(cls, ea, **target):
            res = internal.tagindex.contents.get(ea)
            return True if res else False
        @classmethod
        def get(cls, ea, **target):
            return internal.tagindex.contents.get(ea)
        @classmethod
        def increment(cls, address, name, **target):
            position, counts = internal.tagindex.contents.increment(address, name, **target)
            owner = interface.function.by_address(target.get('target', address))
            return counts.get(interface.range.start(owner), 0)
        @classmethod
        def decrement(cls, address, name, **target):
            position, counts = internal.tagindex.contents.decrement(address, name, **target) if internal.tagindex.tags.has(name) else (0, {})
            owner = interface.function.by_address(target.get('target', address))
            return counts.get(interface.range.start(owner), 0)
        @classmethod
        def iterate(cls):
            iterable = internal.tagindex.contents.select()
            return ((ea, internal.tagindex.tags.names(used)) for ea, used in iterable)
        @classmethod
        def name(cls, address, **target):
            used = internal.tagindex.contents.usage(address)
            return internal.tagindex.tags.names(used)
        @classmethod
        def address(cls, address, **target):
            return [ea for ea, _ in internal.tagindex.contents.function(address)]
        @classmethod
        def counts(cls, address):
            res, used = {}, (integer for ea, integer in internal.tagindex.contents.function(address))
            for name in itertools.chain(*map(internal.tagindex.tags.names, used)):
                res[name] = res.setdefault(name, 0) + 1
            return res
        @classmethod
        def erase_address(cls, func, ea):
            names = internal.tagindex.contents.get(ea)
            removed = [internal.tagindex.contents.decrement(ea, name, target=func) for name in names]
            return len(names)
        @classmethod
        def erase(cls, func):
            return internal.tagindex.contents.erase(func)

    class structure(object):
        """
        This namespace handles the tags that can be applied to a structure or a
        union. This is just a frontend to its implementation which resides in
        the `internal.tagindex.structure` namespace.
        """
        @classmethod
        def has(cls, sid):
            res = internal.tagindex.structure.get(sid)
            return True if res else False
        @classmethod
        def get(cls, sid):
            return internal.tagindex.structure.get(sid)
        @classmethod
        def increment(cls, sid, name):
            position, count = internal.tagindex.structure.increment(sid, name)
            return count
        @classmethod
        def decrement(cls, sid, name):
            position, count = internal.tagindex.structure.decrement(sid, name) if internal.tagindex.tags.has(name) else (0, 0)
            return count
        @classmethod
        def erase(cls, sid):
            return internal.tagindex.structure.erase([sid])

    class members(object):
        """
        This namespace contains all the tools required for tracking the tags
        that have been applied to members belonging to a structure or a union.
        It is primarily just a frontend to its implementation which resides
        within the `internal.tagindex.members` namespace.
        """
        @classmethod
        def has(cls, mid):
            res = internal.tagindex.members.get(mid)
            return True if res else False
        @classmethod
        def get(cls, mid):
            return internal.tagindex.members.get(mid)
        @classmethod
        def increment(cls, mid, name):
            position, count = internal.tagindex.members.increment(mid, name)
            return count
        @classmethod
        def decrement(cls, mid, name):
            position, count = internal.tagindex.members.decrement(mid, name) if internal.tagindex.tags.has(name) else (0, 0)
            return count
        @classmethod
        def erase_member(cls, sid, mid):
            return internal.tagindex.members.erase(sid, [mid])
        @classmethod
        def erase(cls, sid):
            iterable = internal.tagindex.members.structure([sid])
            selected = [mid for mid, used in iterable]
            return internal.tagindex.members.erase([sid], selected)

# Select the v0 frontend by default. This using the functionality provided
# by the tagcache which has since been redesigned into the tagging index.
reference = reference_v0
