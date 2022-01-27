"""
Tagfix module

This module is provided to a user to allow one to rebuild the
cache that is built when a database is finished processing. If
the cache is corrupted through some means, this module can be
used to rebuild the tag-cache by manually scanning the currently
defined tags and resetting its references in order to allow one
to query again.

To manually rebuild the cache for the database, use the following::

    > custom.tagfix.everything()

Likewise to rebuild the cache for just the globals or the contents::

    > custom.tagfix.globals()
    > custom.tagfix.contents()

"""

import six, sys, logging, builtins
import functools, operator, itertools, types

import database as db, function as func, ui
import internal

import idaapi
output = sys.stderr

def fetch_contents(fn):
    """Fetch the reference count for the contents of function `fn` in the database.

    Returns the tuple `(func, address, tags)` where the `address` and
    `tags` fields are both dictionaries containing the reference count for
    the addresses and tag names. The field `func` contains the address of the
    function.
    """
    addr, tags = {}, {}

    for ea in func.iterate(fn):
        ui.navigation.auto(ea)

        # grab both comment types so that we can decode them. after decoding,
        # then iterate through all of their keys and tally up their counts.
        repeatable, nonrepeatable = (db.comment(ea, repeatable=item) for item in [True, False])
        for items in map(internal.comment.decode, [repeatable, nonrepeatable]):
            #items.pop('name', None)
            for name in items:
                addr[ea] = addr.get(ea, 0) + 1
                tags[name] = tags.get(name, 0) + 1
            continue
        continue
    return func.address(fn), addr, tags

def fetch_globals_functions():
    """Fetch the reference count for the global tags (function) in the database.

    Returns the tuple `(address, tags)` where the `address` and `tags`
    fields are both dictionaries containing the reference count for
    the addresses and tag names.
    """
    addr, tags = {}, {}
    functions = [item for item in db.functions()]
    for i, ea in enumerate(functions):
        ui.navigation.auto(ea)
        six.print_(u"globals: fetching tag from function {:#x} : {:d} of {:d}".format(ea, 1 + i, len(functions)), file=output)

        # grab both comment types from the current function and then decode
        # them. once decoded then we can just iterate through their keys and
        # tally everything up.
        repeatable, nonrepeatable = (func.comment(ea, repeatable=item) for item in [True, False])
        for items in map(internal.comment.decode, [repeatable, nonrepeatable]):
            #items.pop('name', None)
            for name in items:
                addr[ea] = addr.get(ea, 0) + 1
                tags[name] = tags.get(name, 0) + 1
            continue
        continue
    return addr, tags

def fetch_globals_data():
    """Fetch the reference count for the global tags (non-function) in the database.

    Returns the tuple `(address, tags)` where the `address` and `tags`
    fields are both dictionaries containing the reference count for
    the addresses and tag names.
    """
    addr, tags = {}, {}
    left, right = db.config.bounds()
    six.print_(u'globals: fetching tags from data', file=output)
    for ea in db.address.iterate(left, right):
        if func.within(ea): continue
        ui.navigation.auto(ea)

        # grab both comment types and decode them. after they've been decoded,
        # then iterate through all of their keys and tally up their counts.
        repeatable, nonrepeatable = (db.comment(ea, repeatable=item) for item in [True, False])
        for items in map(internal.comment.decode, [repeatable, nonrepeatable]):
            #items.pop('name', None)
            for name in items:
                addr[ea] = addr.get(ea, 0) + 1
                tags[name] = tags.get(name, 0) + 1
            continue
        continue
    return addr, tags

def fetch_globals():
    """Fetch the reference count of all of the global tags for both functions and non-functions.

    Returns the tuple `(address, tags)` where the `address` and `tags`
    fields are both dictionaries containing the reference count for
    the addresses and tag names.
    """
    # read addr and tags from all functions/globals
    faddr, ftags = fetch_globals_functions()
    daddr, dtags = fetch_globals_data()

    # consolidate tags into individual dictionaries
    six.print_(u'globals: aggregating results', file=output)
    addr, tags = dict(faddr), dict(ftags)
    for k, v in daddr.items():
        addr[k] = addr.get(k, 0) + v
    for k, v in dtags.items():
        tags[k] = tags.get(k, 0) + v

    six.print_(u"globals: found {:d} addresses".format(len(addr)), file=output)
    six.print_(u"globals: found {:d} tags".format(len(tags)), file=output)

    return addr, tags

def contents(ea):
    '''Re-build the cache for the contents of the function `ea`.'''
    try:
        func.address(ea)
    except internal.exceptions.FunctionNotFoundError:
        return {}, {}

    # read addresses and tags from contents
    ui.navigation.auto(ea)
    logging.debug(u"{:s}.contents({:#x}): Fetching the contents from the function {:#x}.".format('.'.join([__name__]), ea, ea))
    f, addr, tags = fetch_contents(ea)

    # clean out any hidden tag values
    for k in tags.keys():
        if k in {'__tags__', '__address__'}:
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
    logging.debug(u"{:s}.contents({:#x}): Updating the name reference cache for the contents of function {:#x}.".format('.'.join([__name__]), ea, ea))
    for k, v in tags.items():
        internal.comment.contents.set_name(f, k, v)

    logging.debug(u"{:s}.contents({:#x}): Updating the address reference cache for the contents of function {:#x}.".format('.'.join([__name__]), ea, ea))
    for k, v in addr.items():
        if not func.within(k):
            continue
        internal.comment.contents.set_address(k, v)

    return addr, tags

def globals():
    '''Re-build the cache for all of the globals in the database.'''

    # read all function and data tags
    addr, tags = fetch_globals()

    # update the global state
    six.print_(u'globals: updating global name refs', file=output)
    for k, v in tags.items():
        internal.comment.globals.set_name(k, v)

    six.print_(u'globals: updating global address refs', file=output)
    for k, v in addr.items():
        internal.comment.globals.set_address(k, v)

    return addr, tags

def all():
    '''Re-build the cache for all the globals and contents in the database.'''
    functions = [item for item in db.functions()]

    # process all function contents tags
    for i, ea in enumerate(functions):
        six.print_(u"updating references for contents ({:#x}) : {:d} of {:d}".format(ea, 1 + i, len(functions)), file=output)
        _, _ = contents(ea)

    # process all global tags
    six.print_(u'updating references for globals', file=output)
    _, _ = globals()

def customnames():
    '''Iterate through all of the custom names defined in the database and update the cache with their reference counts.'''
    # FIXME: first delete all the custom names '__name__' tag
    left, right = db.config.bounds()
    for ea in db.address.iterate(left, right):
        ctx = internal.comment.contents if func.within(ea) and func.address(ea) != ea else internal.comment.globals
        if db.type.has_customname(ea):
            ctx.inc(ea, '__name__')
        continue
    return

def extracomments():
    '''Iterate through all of the extra comments defined in the database and update the cache with their reference counts.'''
    left, right = db.config.bounds()
    for ea in db.address.iterate(left, right):
        ctx = internal.comment.contents if func.within(ea) else internal.comment.globals

        count = db.extra.__count__(ea, idaapi.E_PREV)
        if count: [ ctx.inc(ea, '__extra_prefix__') for i in range(count) ]

        count = db.extra.__count__(ea, idaapi.E_NEXT)
        if count: [ ctx.inc(ea, '__extra_suffix__') for i in range(count) ]
    return

def everything():
    '''Re-create the cache for all the tags found in the database.'''
    erase()
    all()

def erase_globals():
    '''Erase the cache defined for all of the global tags in the database.'''
    n = internal.comment.tagging.node()
    hashes, alts, sups = res = [list(items) for items in [internal.netnode.hash.fiter(n), internal.netnode.alt.fiter(n), internal.netnode.sup.fiter(n)]]
    total = sum(map(len, res))

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
    for idx, ea in enumerate(alts):
        internal.netnode.alt.remove(n, ea)
        yield current + idx, ea
    return

def erase_contents():
    '''Erase the contents cache defined for each function in the database.'''
    functions = [item for item in db.functions()]
    total, tag = len(functions), internal.comment.contents.btag
    yield total

    for idx, ea in enumerate(functions):
        internal.netnode.blob.remove(ea, tag)
        yield idx, ea
    return

def erase():
    '''Erase the current cache from the database.'''
    iter1, iter2 = erase_contents(), erase_globals()
    total = sum(map(next, [iter1, iter2]))

    current = 0
    for idx, ea in iter1:
        six.print_(u"erasing contents for function {:#x} : {:d} of {:d}".format(ea, 1 + idx, total), file=output)

    res = idx + 1
    for idx, addressOrName in iter2:
        fmt = "{:#x}" if isinstance(addressOrName, six.integer_types) else "tagname {!r}"
        six.print_(u"erasing global {:s} : {:d} of {:d}".format(fmt.format(addressOrName), 1 + res + idx, total), file=output)
    return

def verify_index():
    '''Iterate through the index and verify that each contents entry is pointing at the right functions.'''
    cls, ok = internal.comment.contents, True

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
    cls = internal.comment.contents
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
            six.print_(u"[{:#x}] expected to find {:d} reference{:s} to address {:#x}, whereas {:s} found within the function".format(f, expected[ea], '' if expected[ea] == 1 else '', ea, "{:d} was".format(count) if count == 1 else "{:d} were".format(count)), file=output)
        continue
    return True

__all__ = ['everything', 'globals', 'contents']
