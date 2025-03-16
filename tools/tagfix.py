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

import database as db, function as func, ui
import internal

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
    f, results, counts = func.address(fn), {}, {}
    for ea in map(ui.navigation.analyze, func.iterate(fn)):
        items = db.tag(ea)
        results[ea] = {tag for tag in items}
        for tag in items:
            integer = counts.get(tag, 0)
            counts[tag] = integer + 1
        continue
    return func.address(fn), results, counts

def fetch_globals_functions():
    """Fetch all of the global tags (functions) from the database.

    Returns a list of the tuple `(address, tags)` where each item describes the
    set of tags that have been applied to the function at a given address. This
    can then be used to calculate the reference counts or applied to the
    database in bulk.
    """
    result = []
    functions = [item for item in db.functions.iterate()]
    for i, ea in enumerate(map(ui.navigation.analyze, functions)):
        six.print_(u"globals: collecting the tags that were applied to function {:#x} : {:d} of {:d}".format(ea, 1 + i, len(functions)), file=output)
        result.append((ea, {item for item in func.tag(ea)}))
    return result

def fetch_globals_data():
    """Fetch a list of all the global tags (non-functions) from the database.

    Returns a list of the tuple `(address, tags)` where each item describes the
    set of tags that have been applied to a global address. This list can be
    used to calculate the reference counts of applied to the database in bulk.
    """
    result = []
    left, right = db.information.bounds()
    six.print_(u'globals: collecting any tags that have been applied to a global address', file=output)
    for ea in map(ui.navigation.analyze, db.address.iterate(left, right)):
        if idaapi.get_func(ea):
            continue
        result.append((ea, {item for item in db.tag(ea)}))
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
    try:
        func.address(address)
    except internal.exceptions.FunctionNotFoundError:
        logging.warning(u"{:s}.contents({:#x}): Unable to fetch cache the for the address {:#x} as it is not a function.".format('.'.join([__name__]), address, address))
        return {}, {}

    # Read the addresses and tags from the contents of the function.
    logging.debug(u"{:s}.contents({:#x}): Fetching the cache for the function {:#x}.".format('.'.join([__name__]), address, address))
    f, results, counts = fetch_contents(ui.navigation.procedure(address))
    ui.navigation.set(address)

    # Gather the current reference counts for the function, and update its tags.
    logging.debug(u"{:s}.contents({:#x}): Updating the tag references in the cache belonging to function {:#x}.".format('.'.join([__name__]), address, address))
    original = {tag : count for tag, count in internal.tags.contents.counts(address)}
    for ea, tags in results.items():
        for tag in tags:
            internal.tags.contents.increment(ea, tag, target=address)
        continue
    modified = {tag : count for tag, count in internal.tags.contents.counts(address)}

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
    original = {tag : count for tag, count in internal.tags.globals.counts()}
    for ea, tags in address.items():
        for tag in tags:
            internal.tags.globals.increment(ea, tag)
        continue
    modified = {tag : count for tag, count in internal.tags.globals.counts()}

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
    functions = [item for item in db.functions()]

    # process all function contents tags
    for i, ea in enumerate(functions):
        six.print_(u"updating the cache for the tags belonging to function ({:#x}) : {:d} of {:d}".format(ea, 1 + i, len(functions)), file=output)
        _, _ = contents(ea)

    # process all global tags
    six.print_(u'updating the index for the database with references for all globals', file=output)
    _, _ = globals()

def customnames():
    '''Iterate through all of the "custom" names within the database and update their references in either the index or their associated function cache.'''
    # FIXME: first delete all the custom names '__name__' tag
    left, right = db.config.bounds()
    for ea in db.address.iterate(left, right):
        ctx = internal.tags.reference.contents if func.within(ea) and func.address(ea) != ea else internal.tags.reference.globals
        if db.type.has_customname(ea):
            ctx.increment(ea, '__name__')
        continue
    return

def extracomments():
    '''Iterate through all of the "extra" comments within the database and update their references in either the index or their associated function cache.'''
    left, right = db.config.bounds()
    for ea in db.address.iterate(left, right):
        ctx = internal.tags.reference.contents if func.within(ea) else internal.tags.reference.globals

        count = db.extra.__count__(ea, idaapi.E_PREV)
        if count: [ ctx.increment(ea, '__extra_prefix__') for i in range(count) ]

        count = db.extra.__count__(ea, idaapi.E_NEXT)
        if count: [ ctx.increment(ea, '__extra_suffix__') for i in range(count) ]
    return

def everything():
    '''Rebuild the index for all of the globals and the cache for each function from the database.'''
    erase()
    all()

def erase_globals():
    '''Remove the contents of the index from the database which is used for storing information about the global tags.'''
    addresses = {ea for ea, _ in internal.tags.reference.globals.iterate()}
    names = {tag for tag, _ in internal.tags.reference.globals.counts()}
    total = len(names) + len(addresses)

    yield total

    # XXX: decrementing all referenced tags should result in destroying the
    #      specified tag... but there's a chance that a bug might prevent it.
    #current = 0
    #for idx, k in enumerate(names):
    #    internal.tags.reference.destroy_tag(k)
    #    yield current + idx, k

    current += len(names)
    for idx, ea in enumerate(addresses):
        internal.tags.reference.globals.erase_address(ea)
        yield current + idx, ea
    return

def erase_contents():
    '''Remove the cache associated with each function from the database.'''
    functions = [item for item in db.functions()]
    yield len(functions)

    for idx, ea in enumerate(map(ui.navigation.set, functions)):
        internal.tags.reference.contents.erase(ea)
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

def verify_index():
    '''Iterate through the index and verify that each contents entry is pointing at the right functions.'''
    cls, ok = internal.tags.reference.contents, True

    # Iterate through the entire index of contents.
    for ea, available in cls.iterate():
        if not func.within(ea):
            ok, _ = False, six.print_(u"[{:#x}] the item in the index ({:#x}) has been orphaned and is not associated with a function".format(ea, ea), file=output)
            continue

        # Verify the owner of the address the cache is stored in
        # actually belongs to the correct function.
        f = ui.navigation.analyze(func.address(ea))
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

def verify_content(ea):
    '''Iterate through the contents cache for an individual function and verify that the addresses in its cache are correct.'''
    cls = internal.tags.reference.contents
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
    if not func.within(ea):
        six.print_(u"[{:#x}] the cache at {:#x} is not part of a function".format(ea, ea), file=output)
        return False
    f = func.address(ea)

    # If we verify that the addresses in the cache are all within the
    # function that the cache is associated with, then we're done.
    if not builtins.all(func.contains(f, item) for item in cache[cls.__address__]):
        missed = {item for item in cache[cls.__address__] if not func.contains(f, item)}
        six.print_(u"[{:#x}] the cache references {:d} address{:s} that are not owned by function {:#x}".format(ea, len(missed), '' if len(missed) == 1 else 'es', f), file=output)

        # Otherwise, some of the addresses are pointing to the wrong place.
        for index, item in enumerate(sorted(missed)):
            six.print_(u"[{:#x}] item {:d} of {:d} at {:#x} should be owned by {:#x} but {:s}".format(ea, 1 + index, len(missed), item, f, "is in {:#x}".format(func.address(item)) if func.within(item) else 'is not in a function'), file=output)
        return False

    # Iterate through the cache for a function and store all of the tags
    # that are available for each address. We also keep track of the implicit
    # tags because we're going to do some quirky things to adjust for them.
    results, implicit = {}, {key : [] for key in ['__typeinfo__', '__name__']}
    for ea in cache[cls.__address__]:
        items, empty = {key for key in db.tag(ea)}, {item for item in []}
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

def verify_globals():
    '''Verify the globals for every address from the database.'''
    cls = internal.tags.reference.globals

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
        Ftags = db.tag

        # First figure out how to validate the address. If it's a function,
        # then we can use func.address.
        if func.within(ea):
            f = func.address(ea)
            if f != ea:
                six.print_(u"[{:#x}] the item in the global index ({:#x}) is not at the beginning of a function ({:#x})".format(ea, ea, f), file=output)

            # We can now force the address to point to the actual function
            # address because func.tag will correct this anyways.
            ea, Ftags = f, func.tag

        # In this case we must be a global and we need to use a combination
        # of database.contains, and then interface.address.head.
        elif not db.within(ea):
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
            logging.debug(u"{:s}.verify_globals(): Found {:d} candidate{:s} for the tags ({:s}) belonging to the {:s} at {:#x} that would result in a proper count of {:d} reference{:s}.".format('.'.join([__name__]), len(candidates), '' if len(candidates) == 1 else 's', ', '.join(map("{!r}".format, expected)), 'function' if func.within(ea) else 'address', ea, count, '' if count == 1 else 's'))
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
            ok, _ = False, six.print_(u"[{:#x}] expected to find {:d} reference{:s} at {:s} {:#x}, but found {:s} instead".format(ea, count, '' if count == 1 else 's', 'function' if func.within(ea) else 'address', ea, format(len(expected - largest), len(expected - smallest))))

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

def verify_contents():
    '''Verify the contents of every single function in the index.'''
    index = sorted({ea for ea, _ in internal.tags.reference.contents.iterate()})

    # Verify the index as the very first thing.
    ok = verify_index()
    if not ok:
        six.print_(u'some issues were found within the index... ignoring them and proceeding to verify each cache referenced by the index', file=output)

    # Now we can iterate through the index and process each function's contents.
    i = count = 0
    for i, ea in enumerate(index):
        ok = verify_content(ui.navigation.set(ea))
        count += 1 if ok else 0
    return count, len(index)

def verify():
    '''Use the index to verify the reference counts for the globals, functions, and the caches containing their contents.'''
    verified, available = verify_contents()
    ok = verify_globals()
    six.print_(u"Verification of globals has {:s}. Successfully verified{:s} {:d} of {:d} indexed functions.".format('succeeded' if ok else 'failed', ' only' if verified < available else '', verified, available))
    return ok and verified == available

__all__ = ['everything', 'globals', 'contents']
