"""
Tagfix module

This module is provided to a user to allow one to rebuild the
cache that is built when a database is finished processing. If
the cache is corrupted through some means, this module can be
used to rebuild the tag-cache by manually scanning the currently
defined tags and resetting its references in order to allow one
to query again.

To manually rebuild the cache for the database, use the following::

    > tools.tagfix.everything()

Likewise to rebuild the cache for just the globals or the contents::

    > tools.tagfix.globals()
    > tools.tagfix.contents()

"""

import six, sys, logging, builtins
import functools, operator, itertools, types
logging = logging.getLogger(__name__)

import ui, internal

import idaapi
output = sys.stderr

def fetch_contents(fn):
    """Fetch the tags for the contents of function `fn` from the database.

    Returns the tuple `(function, address, tags)` where the `address` and `tags
    elements are both dictionaries, and the `function` element is the address of
    the function that was processed. The `address` dictionary contains each
    contents address and the tags associated with it. The `tags` dictionary
    contains the reference counts for each of the tags applied to the contents
    of the function `fn`.
    """
    fn, results, counts = internal.interface.function.by(fn), {}, {}
    for start, end in map(internal.interface.range.unpack, internal.interface.function.chunks(fn)):
        for ea in internal.interface.address.items(start, end):
            items = internal.tags.address.get(ea)
            results[ea] = {tag for tag in items}
            for tag in items:
                integer = counts.get(tag, 0)
                counts[tag] = integer + 1
            continue
        continue
    return internal.interface.range.start(fn), results, counts

def fetch_globals_functions():
    """Fetch all of the global tags (functions) from the database.

    Returns a list of the tuple `(address, tags)` where each item describes the
    set of tags that have been applied to the function at a given address. This
    can then be used to calculate the reference counts or applied to the
    database in bulk.
    """
    result = []
    functions = [item for item in internal.interface.function.enumerate()]
    for i, ea in functions:
        ea = ui.navigation.analyze(ea)
        six.print_(u"globals: collecting the tags that were applied to function {:#x} : {:d} of {:d}".format(ea, 1 + i, len(functions)), file=output)
        result.append((ea, {item for item in internal.tags.function.get(ea)}))
    return result

def fetch_globals_data():
    """Fetch a list of all the global tags (non-functions) from the database.

    Returns a list of the tuple `(address, tags)` where each item describes the
    set of tags that have been applied to a global address. This list can be
    used to calculate the reference counts of applied to the database in bulk.
    """
    result = []
    left, right = internal.interface.address.bounds()
    six.print_(u'globals: collecting any tags that have been applied to a global address', file=output)
    for ea in map(ui.navigation.analyze, internal.interface.address.items(left, right)):
        if idaapi.get_func(ea):
            continue
        result.append((ea, {item for item in internal.tags.address.get(ea)}))
    return result

def fetch_globals():
    """Fetch all of the global tags associated with both functions and non-functions from the database.

    Returns the tuple `(address, tags)` where both elements are dictionaries.
    The `address` dictionary contains the tags associated with each global
    address. The `tags` dictionary contains the reference counts for the tags
    being used by the `address` dictionary.
    """
    # Read both the address and tags from all functions and globals.
    fresults = fetch_globals_functions()
    dresults = fetch_globals_data()

    # Consolidate tags into a dictionary, and collect the tags separately.
    results, counts = {}, {}
    six.print_(u'globals: collecting all addresses and tallying the database tags', file=output)
    for ea, tags in itertools.chain(fresults, dresults):
        results[ea] = tags
        for tag in tags:
            integer = counts.setdefault(tag, 0)
            counts[tag] = integer + 1
        continue

    # Output our results to the specified output.
    six.print_(u"globals: found {:d} addresses to include in index".format(len(results)), file=output)
    six.print_(u"globals: found {:d} tags to include in index".format(len(counts)), file=output)
    return results, counts

def contents(address):
    '''Generate the cache for the contents of the function at the given `address`.'''
    if not internal.interface.function.has(address):
        logging.warning(u"{:s}.contents({:#x}): Unable to fetch cache the for the address {:#x} as it is not a function.".format('.'.join([__name__]), address, address))
        return {}, {}

    # Read the addresses and tags from the contents of the function.
    logging.debug(u"{:s}.contents({:#x}): Fetching the cache for the function {:#x}.".format('.'.join([__name__]), address, address))
    f, results, counts = fetch_contents(ui.navigation.procedure(address))
    ui.navigation.set(address)

    # Gather the current reference counts for the function, and update its tags.
    logging.debug(u"{:s}.contents({:#x}): Updating the tag references in the cache belonging to function {:#x}.".format('.'.join([__name__]), address, address))
    original = internal.tags.reference.contents.counts(address)
    for ea, tags in results.items():
        for tag in tags:
            internal.tags.reference.contents.increment(ea, tag, target=address)
        continue
    modified = internal.tags.reference.contents.counts(address)

    # Now we'll go through the original and modified counts to make sure that
    # they correlate to the counts that we tallied when fetching the contents.
    for tag, count in counts.items():
        old, new = original.get(tag, 0), modified.get(tag, 0)
        if new - old != count:
            logging.debug(u"{:s}.contents({:#x}): Expected a reference count change of {:+d} for tag {!r} in function {:#x}, but change was {:+d} ({:d} - {:d}) instead.".format('.'.join([__name__]), address, count, tag, address, new - old, new, old))
        continue

    return {ea : len(tags) for ea, tags in results.items()}, counts

def globals():
    '''Build the index of references for all of the globals in the database.'''

    # Read all of the data tags for each function and address.
    address, counts = fetch_globals()

    # Gather the current reference counts for the globals, and update their tags.
    original = internal.tags.reference.globals.counts()
    for ea, tags in address.items():
        for tag in tags:
            internal.tags.reference.globals.increment(ea, tag)
        continue
    modified = internal.tags.reference.globals.counts()

    # Now we'll go through both counts to make sure that they correlate to the
    # counts that we tallied when fetching all the globals.
    for tag, count in counts.items():
        old, new = original.get(tag, 0), modified.get(tag, 0)
        if new - old != count:
            logging.debug(u"{:s}.globals(): Expected a reference count change of {:+d} for tag {!r} in database, but change was {:+d} ({:d} - {:d}) instead.".format('.'.join([__name__]), count, tag, new - old, new, old))
        continue

    return {ea : len(tags) for ea, tags in address.items()}, counts

def all():
    '''Build the index of references for all the globals and generate the caches for every function in the database.'''
    functions = [item for item in internal.interface.function.enumerate()]

    # process all function contents tags
    for i, ea in functions:
        six.print_(u"updating the cache for the tags belonging to function ({:#x}) : {:d} of {:d}".format(ea, 1 + i, len(functions)), file=output)
        _, _ = contents(ea)

    # process all global tags
    six.print_(u'updating the index for the database with references for all globals', file=output)
    _, _ = globals()

def customnames():
    '''Iterate through all of the "custom" names within the database and update their references in either the index or their associated function cache.'''
    # FIXME: first delete all the custom names '__name__' tag
    left, right = internal.interface.address.bounds()
    for ea in internal.interface.address.items(left, right):
        fn = internal.interface.function.by(ea) if internal.interface.function.has(ea) else None
        if fn is None or internal.interface.range.start(fn) == ea:
            ctx = internal.tags.reference.globals
        else:
            ctx = internal.tags.reference.contents
        if internal.interface.address.flags(ea, idaapi.MS_COMM) & idaapi.FF_NAME:
            ctx.increment(ea, '__name__')
        continue
    return

def extracomments():
    '''Iterate through all of the "extra" comments within the database and update their references in either the index or their associated function cache.'''
    left, right = internal.interface.address.bounds()
    for ea in internal.interface.address.items(left, right):
        fn = internal.interface.function.by(ea) if internal.interface.function.has(ea) else None
        if fn is None or internal.interface.range.start(fn) == ea:
            ctx = internal.tags.reference.globals
        else:
            ctx = internal.tags.reference.contents

        count = internal.comment.extra.count(ea, idaapi.E_PREV)
        if count: [ ctx.increment(ea, '__extra_prefix__') for i in range(count) ]

        count = internal.comment.extra.count(ea, idaapi.E_NEXT)
        if count: [ ctx.increment(ea, '__extra_suffix__') for i in range(count) ]
    return

def everything():
    '''Rebuild the index for all of the globals and the cache for each function from the database.'''
    erase()
    all()

def erase_globals():
    '''Remove the contents of the index from the database which is used for storing information about the global tags.'''
    addresses = {ea for ea, _ in internal.tags.reference.globals.iterate()}
    names = {tag for tag in internal.tags.reference.globals.counts()}
    total = len(names) + len(addresses)

    yield total

    # XXX: decrementing all referenced tags should result in destroying the
    #      specified tag... but there's a chance that a bug might prevent it.
    #current = 0
    #for idx, k in enumerate(names):
    #    internal.tags.reference.destroy_tag(k)
    #    yield current + idx, k

    current = len(names)
    for idx, ea in enumerate(addresses):
        internal.tags.reference.globals.erase_address(ea)
        yield current + idx, ea
    return

def erase_contents():
    '''Remove the cache associated with each function from the database.'''
    functions = [item for item in internal.interface.function.enumerate()]
    yield len(functions)

    for idx, ea in functions:
        internal.tags.reference.contents.erase(ui.navigation.set(ea))
        yield idx, ea
    return

def erase():
    '''Erase the index of all the globals and the cache associated with each function from the database.'''
    iter1, iter2 = erase_contents(), erase_globals()
    total = sum(map(next, [iter1, iter2]))

    current = 0
    for idx, ea in iter1:
        six.print_(u"removing the cache for function {:#x} : {:d} of {:d}".format(ea, 1 + idx, total), file=output)

    res = idx + 1
    for idx, addressOrName in iter2:
        format = "address {:#x}".format if isinstance(addressOrName, six.integer_types) else "tagname {!r}".format
        six.print_(u"removing the global {:s} from the index : {:d} of {:d}".format(format(addressOrName), 1 + res + idx, total), file=output)
    return

def verify_index_v0():
    '''Iterate through the index and verify that each contents entry is pointing at the right functions.'''
    cls, ok = internal.tagcache.contents, True

    # Iterate through the entire index of contents.
    for ea, available in cls.iterate():
        if not internal.interface.function.has(ea):
            ok, _ = False, six.print_(u"[{:#x}] the item in the index ({:#x}) has been orphaned and is not associated with a function".format(ea, ea), file=output)
            continue

        # Verify the owner of the address the cache is stored in
        # actually belongs to the correct function.
        f = ui.navigation.analyze(internal.interface.range.start(internal.interface.function.by(ea)))
        if f != ea:
            ok, _ = False, six.print_(u"[{:#x}] the item has the wrong parent ({:#x}) and should be owned by {:#x}".format(ea, ea, f), file=output)
            continue

        # Verify the keys inside the cache are only ones that we know about.
        expected = {key for key in [cls.__tags__, cls.__address__]}
        keys = {key for key in available}
        if keys - expected:
            ok, _ = False, six.print_(u"[{:#x}] the index item for this function contains unsupported keys ({:s})".format(ea, ', '.join(sorted(keys - expected))), file=output)
            continue

        # Make sure that both keys are contained within the cache.
        if keys != expected:
            ok, _ = False, six.print_(u"[{:#x}] the index item for this function contains keys ({:s}) that do not match the requirements ({:s})".format(ea, ', '.join(keys), ', '.join(expected)), file=output)
        continue
    return ok

def verify_content_v0(ea):
    '''Iterate through the contents cache for an individual function and verify that the addresses in its cache are correct.'''
    cls = internal.tagcache.contents
    try:
        cache = cls._read(ea, ea)

    # We should be within a function, otherwise this can't be verified.
    except internal.exceptions.FunctionNotFoundError:
        six.print_(u"[{:#x}] unable to read the cache for the requested address {:#x}".format(ea, ea), file=output)
        return False

    # If there was no cache, then we can just immediately return.
    if cache is None:
        six.print_(u"[{:#x}] the requested address ({:#x}) does not contain a cache".format(ea, ea), file=output)
        return False

    # Grab the keys from the cache in order to cross-check them.
    expected, available = {key for key in [cls.__tags__, cls.__address__]}, {key for key in cache}

    # Verify that the keys in our cache match what we expect.
    if available - expected:
        six.print_(u"[{:#x}] the cache at {:#x} contains unsupported keys ({:s})".format(ea, ea, ', '.join(sorted(available - expected))), file=output)
        return False

    # Ensure that the cache definitely contains the keys we expect.
    if available != expected:
        six.print_(u"[{:#x}] the cache at {:#x} contains keys ({:s}) that do not meet the requirements ({:s})".format(ea, ea, ', '.join(available), ', '.join(expected)), file=output)
        return False

    # If we're not within a function, then we need to bail because
    # the next tests can't possibly succeed.
    if not internal.interface.function.has(ea):
        six.print_(u"[{:#x}] the cache at {:#x} is not part of a function".format(ea, ea), file=output)
        return False
    f = internal.interface.range.start(internal.interface.function.by(ea))

    # If we verify that the addresses in the cache are all within the
    # function that the cache is associated with, then we're done.
    if not builtins.all(internal.interface.function.has(f, item) for item in cache[cls.__address__]):
        missed = {item for item in cache[cls.__address__] if not internal.interface.function.has(f, item)}
        six.print_(u"[{:#x}] the cache references {:d} address{:s} that are not owned by function {:#x}".format(ea, len(missed), '' if len(missed) == 1 else 'es', f), file=output)

        # Otherwise, some of the addresses are pointing to the wrong place.
        for index, item in enumerate(sorted(missed)):
            six.print_(u"[{:#x}] item {:d} of {:d} at {:#x} should be owned by {:#x} but {:s}".format(ea, 1 + index, len(missed), item, f, "is in {:#x}".format(interface.range.start(interface.function.by(item))) if internal.interface.function.has(item) else 'is not in a function'), file=output)
        return False

    # Iterate through the cache for a function and store all of the tags
    # that are available for each address. We also keep track of the implicit
    # tags because we're going to do some quirky things to adjust for them.
    results, implicit = {}, {key : [] for key in ['__typeinfo__', '__name__']}
    for ea in cache[cls.__address__]:
        items, empty = {key for key in internal.tags.address.get(ea)}, {item for item in []}
        for name in items:
            results.setdefault(ea, empty).add(name)

        # Find the intersection of our tags with the keys for the implicit
        # tags so that we can remember their addresses and query them later.
        for name in {key for key in implicit} & items:
            implicit[name].append(ea)
        continue

    # Sanity check the addresses in our implicit collection as we convert
    # them into a set for a quick membership test. This shouldn't happen,
    # but when verifying things without having to worry about performance
    # cost I don't think it causes too much pain.
    for key in implicit:
        items = {item for item in implicit[key]}
        if len(items) != len(implicit[key]):
            counts = {ea : len([ea for ea in group]) for ea, group in itertools.groupby(implicit[key])}
            six.print_(u"[{:#x}] duplicate addresses were discovered for implicit tag {!r} at: {:s}".format(f, key, ', '.join(ea for ea, count in counts if count > 1)), file=output)
        implicit[key] = items

    # Now we need to do some quirky things to handle some of the implicit
    # tags that are associated with the first address.
    for key, locations in implicit.items():
        count = cache[cls.__tags__].get(key, 0)

        # If the number of locations does not match up to the reference
        # count in the cache, then we also discard as it doesn't match up.
        if operator.contains(locations, f) and len(locations) > count:
            results[f].discard(key)
            continue
        continue

    # Last thing to do is to convert the results that we fixed up into
    # actual counts so that we can check them individually.
    tags, address = {}, {}
    for ea, keys in results.items():
        count = 0
        for item in keys:
            tags[item] = tags.get(item, 0) + 1
            count += 1
        address[ea] = count

    # First we'll verify the address counts.
    expected, available = {ea for ea in cache[cls.__address__]}, {ea for ea in address}
    if expected != available:
        additional, missing = sorted(available - expected), sorted(expected - available)
        six.print_(u"[{:#x}] the address cache for {:#x} is desynchronized and {:s} addresses...".format(f, f, "contains {:d} additional and {:d} missing".format(len(additional), len(missing)) if additional and missing else "is missing {:d}".format(len(missing)) if missing else "has {:d} additional".format(len(additional))), file=output)
        if additional:
            six.print_(u"[{:#x}] ...the additional addresses are: {:s}".format(f, ', '.join(map("{:#x}".format, additional))), file=output)
        if missing:
            six.print_(u"[{:#x}] ...the addresses that are missing are: {:s}".format(f, ', '.join(map("{:#x}".format, missing))), file=output)
        return False

    # Then we'll verify the tag names.
    expected, available = {key for key in cache[cls.__tags__]}, {key for key in tags}
    if expected != available:
        additional, missing = sorted(available - expected), sorted(expected - available)
        six.print_(u"[{:#x}] the name cache for {:#x} is desynchronized and {:s} keys...".format(f, f, "contains {:d} additional and {:d} missing".format(len(additional), len(missing)) if additional and missing else "is missing {:d}".format(len(missing)) if missing else "has {:d} additional".format(len(additional))), file=output)
        if additional:
            six.print_(u"[{:#x}] ...the additional keys are: {:s}".format(f, ', '.join(map("{!r}".format, additional))), file=output)
        if missing:
            six.print_(u"[{:#x}] ...the keys that are missing are: {:s}".format(f, ', '.join(map("{!r}".format, missing))), file=output)
        return False

    # If those were all right, then all critical checks are complete and we
    # can check on the reference counts. Starting with the tag names...
    for key in expected & available:
        expected = cache[cls.__tags__]
        if expected[key] != tags[key]:
            six.print_(u"[{:#x}] expected to find {:d} reference{:s} to tag {!r}, whereas {:s} found within the function".format(f, expected[key], '' if expected[key] == 1 else 's', key, "{:d} was".format(tags[key]) if tags[key] == 1 else "{:d} were".format(tags[key])), file=output)
        continue

    # Now we can compare the address reference counts.
    expected, available = {ea for ea in cache[cls.__address__]}, {ea for ea in address}
    for ea in map(ui.navigation.analyze, expected & available):
        count, expected = address[ea], cache[cls.__address__]

        # This should compare exactly. So if the count doesn't match, let someone know.
        if count != expected[ea]:
            six.print_(u"[{:#x}] expected to find {:d} reference{:s} to address {:#x}, whereas {:s} found within the function".format(f, expected[ea], '' if expected[ea] == 1 else 's', ea, "{:d} was".format(count) if count == 1 else "{:d} were".format(count)), file=output)
        continue
    return True

def verify_globals_v0():
    '''Verify the globals for every address from the database.'''
    cls = internal.tags.reference_v0.globals

    # Calculate all the possible combinations for the implicit tags so that
    # we can use them to figure out which variation will match.
    implicit = {item for item in ['__typeinfo__', '__name__', '__extra_prefix__', '__extra_suffix__']}
    combinations = [{item for item in combination} for combination in itertools.chain(*(itertools.combinations(implicit, length) for length in range(1 + len(implicit))))]
    unique = {item for item in map(tuple, combinations)}
    available = sorted({item for item in items} for items in unique)
    ok, counts, results = True, {}, {}

    # Iterate through the index for the globals and tally up the counts
    # of each tag at the given address. We default with db.tag to fetch
    # them and switch it up only if a function is detected.
    for ea, count in cls.iterate():
        Ftags = internal.tags.address.get

        # First figure out how to validate the address. If it's a function,
        # then we can use func.address.
        if internal.interface.function.has(ea):
            f = internal.interface.range.start(internal.interface.function.by(ea))
            if f != ea:
                six.print_(u"[{:#x}] the item in the global index ({:#x}) is not at the beginning of a function ({:#x})".format(ea, ea, f), file=output)

            # We can now force the address to point to the actual function
            # address because func.tag will correct this anyways.
            ea, Ftags = f, internal.tags.function.get

        # In this case we must be a global and we need to use a combination
        # of database.contains, and then interface.address.head.
        elif not internal.interface.bounds_t(*internal.interface.address.bounds()).contains(ea):
            ok, _ = False, six.print_(u"[{:#x}] the item in the global index ({:#x}) is not within the boundaries of the database".format(ea, ea), file=output)
            continue

        # If we're in the bounds of the database, then we can always succeed
        # as db.tag will correct the address regardless of what we do.
        elif internal.interface.address.head(ea, silent=True) != ea:
            six.print_(u"[{:#x}] the item in the global index ({:#x}) is not pointing at the head of its address ({:#x})".format(ea, ea, internal.interface.address.head(ea, silent=True)), file=output)

        # Now we can align its address and count the number of tags.
        ea = internal.interface.address.head(ui.navigation.set(ea), silent=True)
        expected = {tag for tag in Ftags(ea)}

        # When we do this, we have to figure out whether the implicit tags
        # were actually indexed which we accomplish by generating all possible
        # combinations and figuring out which one is the right one.
        matches = [combination for combination in available if combination & expected == combination]
        if count in {len(expected - match) for match in matches}:
            candidates = [match for match in matches if len(expected - match) == count]
            logging.debug(u"{:s}.verify_globals(): Found {:d} candidate{:s} for the tags ({:s}) belonging to the {:s} at {:#x} that would result in a proper count of {:d} reference{:s}.".format('.'.join([__name__]), len(candidates), '' if len(candidates) == 1 else 's', ', '.join(map("{!r}".format, expected)), 'function' if internal.interface.function.has(ea) else 'address', ea, count, '' if count == 1 else 's'))
            format = functools.partial(u"{:s}.verify_globals(): ...Candidate #{:d} would remove {:s}{:s} resulting in: {:s}.".format, '.'.join([__name__]))
            [logging.debug(format(1 + index, "{:d} tag".format(len(listable)) if len(listable) == 1 else "{:d} tags".format(len(listable)), ", {:s}{:s}".format(', '.join(map("{!r}".format, listable[:-1])), ", and {!r},".format(*listable[-1:]) if len(listable) > 1 else ", {!r},".format(*listable)) if listable else '', ', '.join(map("{!r}".format, expected - candidate)))) for index, (candidate, listable) in enumerate(zip(candidates, map(sorted, candidates)))]

        # If the count wasn't in our list of possible matches, then this address
        # has a bunk reference count and we need to explain the to the user.
        else:
            # FIXME: Make sure this it outputting the results properly.
            smallest, largest = min(available, key=len) if available else {item for item in []}, max(available, key=len) if available else {item for item in []}
            if len(largest) == len(smallest):
                format = "{:d} reference".format if len(expected) == 1 else "{:d} references".format
            elif len(largest) > len(smallest):
                format = "{:d} to {:d} references".format if len(largest) - len(smallest) > 0 and len(expected) > 0 else "{:d} references".format
            else:
                format = "{:d} references".format
            ok, _ = False, six.print_(u"[{:#x}] expected to find {:d} reference{:s} at {:s} {:#x}, but found {:s} instead".format(ea, count, '' if count == 1 else 's', 'function' if internal.interface.function.has(ea) else 'address', ea, format(len(expected - largest), len(expected - smallest))))

        # First tally up all of the counts that aren't affected by implicit tags.
        for key in expected - implicit:
            counts[key] = counts.get(key, 0) + 1

        # Now we need to tally the implicit tags for the given address. We key
        # this by the index of the available combinations so that we have multiple
        # counts for each set of implicit tags that we can later compare.
        for index, choice in enumerate(available):
            for key in expected & choice:
                candidates = results.setdefault(key, {})
                candidates[index] = candidates.get(index, 0) + 1
            continue
        continue

    # That was everything, now we just got to verify our global number of
    # references for each specific tag that isn't implicit.
    references = {key : count for key, count in cls.counts()}
    tags = {tag for tag in references}
    for key in tags - implicit:
        count = references[key]
        if key not in counts:
            ok, _ = False, six.print_(u"[{:s}] unable to locate the referenced tag ({!r}) in the database index".format(key, key))
        elif count != counts[key]:
            ok, _ = False, six.print_(u"[{:s}] expected to find {:d} reference{:s} for the explicit tag {!r}, whereas {:s} found within the database.".format(key, count, '' if count == 1 else 's', key, "{:d} was".format(counts[key]) if counts[key] == 1 else "{:d} were".format(counts[key])), file=output)
        continue

    # The very last thing to do is to verify the tag counts for the implicit
    # tags. This requires us to go through the results and find an index that
    # matches what was written into the global index.
    for key in tags & implicit:
        count, candidates = references[key], {candidate for _, candidate in results.get(key, {}).items()}
        logging.debug(u"{:s}.verify_globals(): Found {:d} candidate{:s} ({:s}) for the implicit tag ({!r}) while searching for a count of {:d}.".format('.'.join([__name__]), len(candidates), '' if len(candidates) == 1 else 's', ', '.join(map("{:d}".format, sorted(candidates))), key, count))
        if not candidates:
            ok, _ = False, six.print_(u"[{:s}] unable to locate the referenced implicit tag ({!r}) in the database index".format(key, key))
        elif not operator.contains(candidates, count):
            ok, _ = False, six.print_(u"[{:s}] expected to find {:d} reference{:s} for the implicit tag ({!r}) in the list of candidates ({:s})".format(key, count, '' if count == 1 else 's', key, ', '.join(map("{:d}".format, candidates))), file=output)
        continue
    return ok

def verify_contents_v0():
    '''Verify the contents of every single function in the index.'''
    index = sorted({ea for ea, _ in internal.tags.reference_v0.contents.iterate()})

    # Verify the index as the very first thing.
    ok = verify_index_v0()
    if not ok:
        six.print_(u'some issues were found within the index... ignoring them and proceeding to verify each cache referenced by the index', file=output)

    # Now we can iterate through the index and process each function's contents.
    i = count = 0
    for i, ea in enumerate(index):
        ok = verify_content_v0(ui.navigation.set(ea))
        count += 1 if ok else 0
    return count, len(index)

def verify_v0():
    '''Use the index to verify the reference counts for the globals, functions, and the caches containing their contents.'''
    verified, available = verify_contents_v0()
    ok = verify_globals_v0()
    six.print_(u"Verification of globals has {:s}. Successfully verified{:s} {:d} of {:d} indexed functions.".format('succeeded' if ok else 'failed', ' only' if verified < available else '', verified, available))
    return ok and verified == available

def upgrade_globals_v1():
    '''Upgrade the global tags stored in the tagcache (v0) to the tagindex (v1).'''
    oldcount = newcount = 0
    for ea, count in internal.tagcache.globals.iterate():
        context = internal.tags.function if internal.interface.function.has(ea) else internal.tags.address
        res = context.get(ea)
        oldcount += count
        newcount += len([internal.tagindex.globals.increment(ea, name) for name in res])
    return oldcount, newcount

def upgrade_function_v1(func):
    '''Upgrade the content tags stored in the tagcache (v0) for the function `func` to the tagindex (v1).'''
    oldcount = newcount = 0
    for ea in internal.tagcache.contents.address(func, target=func):
        res = internal.tags.address.get(ea)
        oldcount += internal.tagcache.contents.count(ea, target=ea)
        newcount += len([internal.tagindex.contents.increment(ea, name, target=func) for name in res])
    return oldcount, newcount

def upgrade_functions_v1():
    '''Upgrade the content tags stored in the tagcache (v0) to the tagindex (v1).'''
    oldcount = newcount = 0
    for ea in internal.interface.function.iterate():
        old, new = upgrade_function_v1(ea)
        oldcount += old
        newcount += new
    return oldcount, newcount

def upgrade_structures_v1():
    '''Upgrade the structure tags to the tagindex (v1).'''
    oldcount = newcount = 0
    for sptr in internal.structure.iterate():
        res = internal.tags.structure.get(sptr)
        oldcount += len(res)
        newcount += len([internal.tagindex.structure.increment(sptr.id, name) for name in res])
    return oldcount, newcount

def upgrade_members_v1():
    '''Upgrade the structure tags to the tagindex (v1).'''
    oldcount = newcount = 0
    for sptr in internal.structure.iterate():
        for mowner, mindex, mptr in internal.structure.members.iterate(sptr):
            res = internal.tags.member.get(mptr)
            oldcount += len(res)
            newcount += len([internal.tagindex.members.increment(mptr.id, name) for name in res])
        continue
    return oldcount, newcount

def upgrade_v1():
    '''Upgrade the tags from the tagcache (v0) to the tagindex (v1).'''
    oldcount = newcount = 0
    old, new = upgrade_globals_v1()
    oldcount, newcount = oldcount + old, newcount + new
    old, new = upgrade_functions_v1()
    oldcount, newcount = oldcount + old, newcount + new
    old, new = upgrade_structures_v1()
    oldcount, newcount = oldcount + old, newcount + new
    old, new = upgrade_members_v1()
    oldcount, newcount = oldcount + old, newcount + new
    return oldcount, newcount

__all__ = ['everything', 'globals', 'contents']
