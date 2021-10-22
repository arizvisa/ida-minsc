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

import six, sys, logging
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
        six.print_(u"globals: fetching tag from function {:#x} : {:d} of {:d}".format(ea, i, len(functions)), file=output)

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
        six.print_(u"updating references for contents ({:#x}) : {:d} of {:d}".format(ea, i, len(functions)), file=output)
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
    hashes, alts, sups = res = [list(items) for items in [internal.netnode.hash.fiter(n), internal.netnode.alt.fitems(n), internal.netnode.sup.fiter(n)]]
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
    for idx, (ea, _) in enumerate(alts):
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
        six.print_(u"erasing contents for function {:#x} : {:d} of {:d}".format(ea, idx, total), file=output)

    res = idx + 1
    for idx, addressOrName in iter2:
        fmt = "{:#x}" if isinstance(addressOrName, six.integer_types) else "tagname {!r}"
        six.print_(u"erasing global {:s} : {:d} of {:d}".format(fmt.format(addressOrName), res+idx, total), file=output)
    return

__all__ = ['everything', 'globals', 'contents']
